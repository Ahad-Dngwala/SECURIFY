"""
main.py — SECURIFY IDS FastAPI Backend
========================================
Endpoints:
  GET  /                   → health check
  GET  /simulate           → generate a random event + prediction + SHAP
  POST /predict            → predict on a user-supplied event JSON
  GET  /stats              → aggregate statistics (call count, attack rate)
  GET  /simulate/batch     → bulk simulate N events and return all results
"""

import random
import sys
import os
from typing import Any

# ── ensure the model/ package is importable regardless of cwd ─────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from model.explain import build_feature_vector, explain_prediction, load_artifacts

# ── app setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SECURIFY — Multi-Cloud IDS",
    description=(
        "Real-time intrusion detection for AWS / Azure / GCP environments. "
        "Each prediction is accompanied by SHAP-based feature attributions for explainability."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── in-memory stats counter ───────────────────────────────────────────────────
_stats = {"total_predictions": 0, "total_attacks": 0}


# ── request / response schemas ────────────────────────────────────────────────
class EventInput(BaseModel):
    cloud_source: str                    = Field("AWS",    example="AWS")
    src_ip: str                          = Field("1.2.3.4", example="203.0.113.45")
    country: str                         = Field("US",     example="RU")
    http_method: str                     = Field("GET",    example="POST")
    endpoint: str                        = Field("/api/auth/login", example="/api/admin/users")
    user_agent: str                      = Field("Mozilla/5.0", example="sqlmap/1.7.8#stable")
    request_rate: float                  = Field(5.0,  ge=0)
    failed_logins: int                   = Field(0,    ge=0)
    data_transferred_mb: float           = Field(1.0,  ge=0)
    session_duration_sec: int            = Field(300,  ge=0)
    privilege_escalation_attempts: int   = Field(0,    ge=0)
    port_scan_detected: int              = Field(0,    ge=0, le=1)
    geo_anomaly: int                     = Field(0,    ge=0, le=1)
    unusual_time_access: int             = Field(0,    ge=0, le=1)
    response_code: int                   = Field(200)
    payload_size_bytes: int              = Field(512,  ge=0)


class ExplanationItem(BaseModel):
    feature: str
    impact: float


class PredictionResponse(BaseModel):
    is_attack: bool
    attack_probability: float
    cloud_source: str
    src_ip: str
    severity: str
    explanation: list[ExplanationItem]


# ── helpers ───────────────────────────────────────────────────────────────────
CLOUD_PROVIDERS = ["AWS", "Azure", "GCP"]
ENDPOINTS_LIST  = [
    "/api/auth/login", "/api/data/export", "/api/admin/users",
    "/api/storage/upload", "/api/compute/spawn", "/api/billing/invoice",
    "/api/iam/policy", "/api/logs/query",
]
HTTP_METHODS    = ["GET", "POST", "PUT", "DELETE", "PATCH"]
USER_AGENTS     = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Boto3/1.26.0",
    "Nmap-Scanner/7.94",
    "sqlmap/1.7.8#stable",
]
COUNTRIES       = ["US", "IN", "GB", "DE", "CN", "RU", "NG", "BR"]


VALID_ATTACK_TYPES = {"brute_force", "data_exfil", "port_scan", "priv_esc", "ddos"}


def _apply_attack(base: dict[str, Any], attack_type: str) -> None:
    """Mutate *base* in-place with feature values matching *attack_type*."""
    if attack_type == "brute_force":
        base.update(
            request_rate=round(random.uniform(50, 300), 2),
            failed_logins=random.randint(20, 200),
            data_transferred_mb=round(random.uniform(0.1, 5.0), 2),
            session_duration_sec=random.randint(10, 120),
            privilege_escalation_attempts=0,
            port_scan_detected=0,
            geo_anomaly=random.randint(0, 1),
            unusual_time_access=1,
        )
    elif attack_type == "data_exfil":
        base.update(
            request_rate=round(random.uniform(5, 50), 2),
            failed_logins=random.randint(0, 5),
            data_transferred_mb=round(random.uniform(500, 5000), 2),
            session_duration_sec=random.randint(100, 600),
            privilege_escalation_attempts=0,
            port_scan_detected=0,
            geo_anomaly=1,
            unusual_time_access=random.randint(0, 1),
            payload_size_bytes=random.randint(100000, 5000000),
        )
    elif attack_type == "port_scan":
        base.update(
            request_rate=round(random.uniform(100, 1000), 2),
            failed_logins=random.randint(0, 5),
            data_transferred_mb=round(random.uniform(0.01, 1.0), 2),
            session_duration_sec=random.randint(1, 60),
            privilege_escalation_attempts=0,
            port_scan_detected=1,
            geo_anomaly=0,
            unusual_time_access=0,
            payload_size_bytes=random.randint(20, 200),
        )
    elif attack_type == "priv_esc":
        base.update(
            request_rate=round(random.uniform(2, 20), 2),
            failed_logins=random.randint(5, 30),
            data_transferred_mb=round(random.uniform(0.5, 10), 2),
            session_duration_sec=random.randint(60, 900),
            privilege_escalation_attempts=random.randint(3, 20),
            port_scan_detected=0,
            geo_anomaly=random.randint(0, 1),
            unusual_time_access=1,
        )
    elif attack_type == "ddos":
        base.update(
            request_rate=round(random.uniform(1000, 10000), 2),
            failed_logins=0,
            data_transferred_mb=round(random.uniform(1, 50), 2),
            session_duration_sec=random.randint(1, 20),
            privilege_escalation_attempts=0,
            port_scan_detected=random.randint(0, 1),
            geo_anomaly=0,
            unusual_time_access=0,
        )


def _make_base_event() -> dict[str, Any]:
    return {
        "cloud_source": random.choice(CLOUD_PROVIDERS),
        "src_ip": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
        "country": random.choice(COUNTRIES),
        "http_method": random.choice(HTTP_METHODS),
        "endpoint": random.choice(ENDPOINTS_LIST),
        "user_agent": random.choice(USER_AGENTS),
        "response_code": 200,
        "payload_size_bytes": random.randint(50, 5000),
    }


def _random_event() -> dict[str, Any]:
    """Create a plausible random event (mix of normal and attack characteristics)."""
    base = _make_base_event()

    if random.random() < 0.35:
        _apply_attack(base, random.choice(list(VALID_ATTACK_TYPES)))
    else:
        base.update(
            request_rate=round(random.uniform(1, 25), 2),
            failed_logins=random.randint(0, 2),
            data_transferred_mb=round(random.uniform(0.1, 50), 2),
            session_duration_sec=random.randint(30, 3600),
            privilege_escalation_attempts=0,
            port_scan_detected=0,
            geo_anomaly=0,
            unusual_time_access=random.randint(0, 1),
        )

    return base


def _forced_attack_event(attack_type: str) -> dict[str, Any]:
    """Create an event that is guaranteed to exhibit *attack_type* characteristics."""
    base = _make_base_event()
    _apply_attack(base, attack_type)
    return base


def _severity(prob: float) -> str:
    if prob >= 0.85:
        return "CRITICAL"
    if prob >= 0.65:
        return "HIGH"
    if prob >= 0.45:
        return "MEDIUM"
    return "LOW"


def _run_prediction(event: dict[str, Any]) -> PredictionResponse:
    model, _, _, _ = load_artifacts()

    fv         = build_feature_vector(event)
    proba      = float(model.predict_proba(fv)[0, 1])
    is_attack  = bool(proba >= 0.5)
    explanation = explain_prediction(fv, top_n=5)

    _stats["total_predictions"] += 1
    if is_attack:
        _stats["total_attacks"] += 1

    return PredictionResponse(
        is_attack=is_attack,
        attack_probability=round(proba, 4),
        cloud_source=event.get("cloud_source", "Unknown"),
        src_ip=event.get("src_ip", "0.0.0.0"),
        severity=_severity(proba),
        explanation=explanation,
    )


# ── routes ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    """Pre-load model artefacts on startup to avoid cold-start latency."""
    try:
        load_artifacts()
        print("✅ Model artefacts loaded successfully.")
    except FileNotFoundError as e:
        print(f"⚠️  Warning: {e}")
        print("   The /simulate and /predict endpoints will fail until you train the model.")


@app.get("/", tags=["Health"])
def health_check():
    return {
        "service": "SECURIFY IDS Backend",
        "status": "operational",
        "version": "1.0.0",
    }


@app.get("/simulate", response_model=PredictionResponse, tags=["Detection"])
def simulate_event():
    """
    Generate a random cloud event, run the IDS model on it, and return
    the prediction with SHAP explanations.
    """
    try:
        event = _random_event()
        return _run_prediction(event)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")


@app.get("/simulate/attack", response_model=PredictionResponse, tags=["Detection"])
def simulate_specific_attack(
    type: str = Query(
        ...,
        description="Attack type to simulate",
        enum=list(VALID_ATTACK_TYPES),
    ),
):
    """
    Force-simulate one event with a specific attack type.
    Used by the frontend attack simulator panel.
    """
    if type not in VALID_ATTACK_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid attack type. Choose from: {VALID_ATTACK_TYPES}")
    try:
        event = _forced_attack_event(type)
        return _run_prediction(event)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")


@app.get(
    "/simulate/batch",
    tags=["Detection"],
    summary="Bulk simulate N events",
)
def simulate_batch(
    n: int = Query(default=10, ge=1, le=200, description="Number of events to simulate"),
):
    """Return a list of N simulated predictions — useful for dashboard demos."""
    try:
        results = []
        for _ in range(n):
            event = _random_event()
            results.append(_run_prediction(event).model_dump())
        return {"count": n, "results": results}
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict", response_model=PredictionResponse, tags=["Detection"])
def predict(event: EventInput):
    """
    Submit a cloud event for intrusion analysis.
    Returns a probability score, severity level, and top-5 SHAP explanations.
    """
    try:
        return _run_prediction(event.model_dump())
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")


@app.get("/stats", tags=["Analytics"])
def get_stats():
    """Return aggregate prediction statistics since server startup."""
    total = _stats["total_predictions"]
    attacks = _stats["total_attacks"]
    attack_rate = round(attacks / total * 100, 2) if total > 0 else 0.0
    return {
        "total_predictions": total,
        "total_attacks": attacks,
        "normal_events": total - attacks,
        "attack_rate_percent": attack_rate,
    }
