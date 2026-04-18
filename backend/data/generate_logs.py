"""
generate_logs.py
Generates 10,000 rows of realistic synthetic multi-cloud access logs.
Each row simulates a single request event originating from AWS, Azure, or GCP.
~20 % of records are labelled as attacks (is_attack = 1).
"""

import random
import numpy as np
import pandas as pd
from faker import Faker

fake = Faker()
random.seed(42)
np.random.seed(42)

CLOUD_PROVIDERS = ["AWS", "Azure", "GCP"]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
ENDPOINTS = [
    "/api/auth/login",
    "/api/data/export",
    "/api/admin/users",
    "/api/storage/upload",
    "/api/compute/spawn",
    "/api/billing/invoice",
    "/api/iam/policy",
    "/api/logs/query",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Boto3/1.26.0",
    "Go-http-client/2.0",
    "Googlebot/2.1",
    "Nmap-Scanner/7.94",       # suspicious
    "sqlmap/1.7.8#stable",     # malicious
]
COUNTRIES = ["US", "IN", "GB", "DE", "CN", "RU", "NG", "BR", "FR", "JP"]


def generate_normal_event(cloud: str) -> dict:
    """Creates a benign log record."""
    return {
        "cloud_source": cloud,
        "src_ip": fake.ipv4_public(),
        "country": random.choice(["US", "IN", "GB", "DE", "FR", "JP"]),
        "http_method": random.choice(["GET", "POST"]),
        "endpoint": random.choice(ENDPOINTS),
        "user_agent": random.choice(USER_AGENTS[:6]),
        "request_rate": round(random.uniform(1.0, 25.0), 2),          # req/sec
        "failed_logins": random.randint(0, 2),
        "data_transferred_mb": round(random.uniform(0.1, 50.0), 2),
        "session_duration_sec": random.randint(30, 3600),
        "privilege_escalation_attempts": 0,
        "port_scan_detected": 0,
        "geo_anomaly": 0,
        "unusual_time_access": random.randint(0, 1),
        "response_code": random.choice([200, 200, 200, 201, 204, 304]),
        "payload_size_bytes": random.randint(50, 5000),
        "is_attack": 0,
    }


def generate_attack_event(cloud: str) -> dict:
    """Creates a malicious log record — various attack types."""
    attack_type = random.choice(["brute_force", "data_exfil", "port_scan", "priv_esc", "ddos"])

    base = {
        "cloud_source": cloud,
        "src_ip": fake.ipv4_public(),
        "country": random.choice(COUNTRIES),
        "http_method": random.choice(HTTP_METHODS),
        "endpoint": random.choice(ENDPOINTS),
        "user_agent": random.choice(USER_AGENTS),
        "request_rate": 0.0,
        "failed_logins": 0,
        "data_transferred_mb": 0.0,
        "session_duration_sec": 0,
        "privilege_escalation_attempts": 0,
        "port_scan_detected": 0,
        "geo_anomaly": 0,
        "unusual_time_access": 0,
        "response_code": random.choice([400, 401, 403, 404, 429, 500, 200]),
        "payload_size_bytes": 0,
        "is_attack": 1,
    }

    if attack_type == "brute_force":
        base.update(
            failed_logins=random.randint(20, 200),
            request_rate=round(random.uniform(30.0, 200.0), 2),
            unusual_time_access=1,
            geo_anomaly=random.randint(0, 1),
            payload_size_bytes=random.randint(100, 500),
        )
    elif attack_type == "data_exfil":
        base.update(
            data_transferred_mb=round(random.uniform(500.0, 5000.0), 2),
            session_duration_sec=random.randint(100, 600),
            request_rate=round(random.uniform(5.0, 50.0), 2),
            geo_anomaly=1,
            payload_size_bytes=random.randint(100000, 5000000),
        )
    elif attack_type == "port_scan":
        base.update(
            port_scan_detected=1,
            request_rate=round(random.uniform(50.0, 500.0), 2),
            failed_logins=random.randint(0, 5),
            payload_size_bytes=random.randint(20, 200),
        )
    elif attack_type == "priv_esc":
        base.update(
            privilege_escalation_attempts=random.randint(3, 20),
            failed_logins=random.randint(5, 30),
            geo_anomaly=random.randint(0, 1),
            unusual_time_access=1,
            payload_size_bytes=random.randint(200, 2000),
        )
    elif attack_type == "ddos":
        base.update(
            request_rate=round(random.uniform(500.0, 5000.0), 2),
            session_duration_sec=random.randint(1, 30),
            port_scan_detected=random.randint(0, 1),
            payload_size_bytes=random.randint(50, 1500),
        )

    return base


def generate_dataset(n: int = 10000, attack_ratio: float = 0.20) -> pd.DataFrame:
    records = []
    n_attack = int(n * attack_ratio)
    n_normal = n - n_attack

    for _ in range(n_normal):
        cloud = random.choice(CLOUD_PROVIDERS)
        records.append(generate_normal_event(cloud))

    for _ in range(n_attack):
        cloud = random.choice(CLOUD_PROVIDERS)
        records.append(generate_attack_event(cloud))

    df = pd.DataFrame(records).sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    import os

    output_path = os.path.join(os.path.dirname(__file__), "cloud_logs.csv")
    df = generate_dataset(n=10000, attack_ratio=0.20)
    df.to_csv(output_path, index=False)

    print(f"✅ Dataset generated → {output_path}")
    print(f"   Total rows  : {len(df)}")
    print(f"   Normal rows : {(df['is_attack'] == 0).sum()}")
    print(f"   Attack rows : {(df['is_attack'] == 1).sum()}")
    print(f"\nSample preview:\n{df.head(3).to_string()}")
