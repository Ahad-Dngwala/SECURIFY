"""
explain.py
Utility helpers consumed by the FastAPI layer.
Compatible with SHAP 0.45.x

  - load_artifacts()        → loads model + SHAP explainer + feature list
  - build_feature_vector()  → encodes raw event dict into numpy array
  - explain_prediction()    → returns top-N SHAP contributions for one row
"""

import os
import joblib
import numpy as np
from typing import Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_model     = None
_explainer = None
_features  = None
_encoders  = None


def load_artifacts():
    """Load all saved artefacts (idempotent — cached after first call)."""
    global _model, _explainer, _features, _encoders

    if _model is not None:
        return _model, _explainer, _features, _encoders

    model_path     = os.path.join(BASE_DIR, "rf_model.pkl")
    explainer_path = os.path.join(BASE_DIR, "shap_explainer.pkl")
    features_path  = os.path.join(BASE_DIR, "feature_names.pkl")
    encoders_path  = os.path.join(BASE_DIR, "label_encoders.pkl")

    for p in [model_path, explainer_path, features_path, encoders_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(
                f"Artefact missing: {p}\n"
                "Run  python backend/model/train_model.py  to generate it."
            )

    _model     = joblib.load(model_path)
    _explainer = joblib.load(explainer_path)
    _features  = joblib.load(features_path)
    _encoders  = joblib.load(encoders_path)

    return _model, _explainer, _features, _encoders


def build_feature_vector(event: dict[str, Any]) -> np.ndarray:
    """
    Convert a raw event dict into the numeric feature vector expected by the model.
    Categorical columns are label-encoded using the saved encoders; unseen
    labels are mapped to 0 (unknown).
    """
    _, _, features, encoders = load_artifacts()

    NUMERIC = [
        "request_rate", "failed_logins", "data_transferred_mb",
        "session_duration_sec", "privilege_escalation_attempts",
        "port_scan_detected", "geo_anomaly", "unusual_time_access",
        "response_code", "payload_size_bytes",
    ]
    CATEGORICALS = ["cloud_source", "country", "http_method", "endpoint", "user_agent"]

    row = []
    for col in NUMERIC:
        row.append(float(event.get(col, 0.0)))

    for col in CATEGORICALS:
        le  = encoders[col]
        val = str(event.get(col, ""))
        if val in le.classes_:
            row.append(int(le.transform([val])[0]))
        else:
            row.append(0)

    return np.array(row, dtype=np.float64).reshape(1, -1)


def explain_prediction(feature_vector: np.ndarray, top_n: int = 5) -> list[dict]:
    """
    Run SHAP on a single-row feature vector and return the top_n most
    impactful features with their signed SHAP values.
    Compatible with SHAP 0.45.x TreeExplainer output format.
    """
    _, explainer, features, _ = load_artifacts()

    shap_values = explainer.shap_values(feature_vector)

    # SHAP 0.45.x: shap_values is a list [neg_class_array, pos_class_array]
    # Each array has shape (1, n_features)
    if isinstance(shap_values, list) and len(shap_values) == 2:
        vals = shap_values[1][0]   # attack class, first (only) row
    elif isinstance(shap_values, list) and len(shap_values) == 1:
        vals = shap_values[0][0]
    elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        # Some versions: shape (1, n_features, 2)
        vals = shap_values[0, :, 1]
    else:
        vals = np.array(shap_values).flatten()[:len(features)]

    pairs = sorted(
        zip(features, vals.tolist()),
        key=lambda x: abs(x[1]),
        reverse=True,
    )[:top_n]

    return [{"feature": f, "impact": round(v, 4)} for f, v in pairs]
