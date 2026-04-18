"""
train_model.py
Trains a Random Forest classifier on the generated cloud_logs.csv.
Saves:
  - rf_model.pkl         → trained model
  - shap_explainer.pkl   → TreeExplainer for inference-time SHAP
  - feature_names.pkl    → ordered feature list used during training
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder

# ── paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH  = os.path.join(BASE_DIR, "..", "data", "cloud_logs.csv")
MODEL_PATH = os.path.join(BASE_DIR, "rf_model.pkl")
SHAP_PATH  = os.path.join(BASE_DIR, "shap_explainer.pkl")
FEAT_PATH  = os.path.join(BASE_DIR, "feature_names.pkl")


# ── feature engineering ──────────────────────────────────────────────────────
CATEGORICAL_COLS = ["cloud_source", "country", "http_method", "endpoint", "user_agent"]
TARGET_COL       = "is_attack"

NUMERIC_FEATURES = [
    "request_rate",
    "failed_logins",
    "data_transferred_mb",
    "session_duration_sec",
    "privilege_escalation_attempts",
    "port_scan_detected",
    "geo_anomaly",
    "unusual_time_access",
    "response_code",
    "payload_size_bytes",
]


def load_and_prepare(path: str):
    df = pd.read_csv(path)
    print(f"Loaded {len(df)} rows from {path}")

    # label-encode categoricals
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col + "_enc"] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    encoded_cols = [c + "_enc" for c in CATEGORICAL_COLS]
    feature_cols = NUMERIC_FEATURES + encoded_cols

    X = df[feature_cols].values
    y = df[TARGET_COL].values
    return X, y, feature_cols, encoders


def train(X, y, feature_cols):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # ── evaluation ────────────────────────────────────────────────────────────
    y_pred  = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\n── Classification Report ──────────────────────────────────────")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    print(f"ROC-AUC : {roc_auc_score(y_test, y_proba):.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # 5-fold cross validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X, y, cv=cv, scoring="roc_auc", n_jobs=-1)
    print(f"\n5-Fold CV AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # feature importance table
    importances = pd.Series(clf.feature_importances_, index=feature_cols)
    print("\nTop-10 Feature Importances:")
    print(importances.nlargest(10).to_string())

    return clf, X_train


def build_shap_explainer(clf, X_train, feature_cols):
    """Build a SHAP TreeExplainer using a background sample."""
    print("\nBuilding SHAP TreeExplainer (background = 200 samples)…")
    background = shap.maskers.Independent(X_train, max_samples=200)
    explainer  = shap.TreeExplainer(clf, data=background, feature_names=feature_cols)
    print("SHAP explainer ready.")
    return explainer


if __name__ == "__main__":
    print("=" * 60)
    print("  SECURIFY — IDS Model Training")
    print("=" * 60)

    if not os.path.exists(DATA_PATH):
        sys.exit(
            f"❌ Dataset not found at {DATA_PATH}\n"
            "   Run:  python backend/data/generate_logs.py  first."
        )

    X, y, feature_cols, encoders = load_and_prepare(DATA_PATH)
    clf, X_train = train(X, y, feature_cols)
    explainer    = build_shap_explainer(clf, X_train, feature_cols)

    # ── save artefacts ────────────────────────────────────────────────────────
    joblib.dump(clf,          MODEL_PATH)
    joblib.dump(explainer,    SHAP_PATH)
    joblib.dump(feature_cols, FEAT_PATH)
    # also persist encoders beside the model
    joblib.dump(encoders, os.path.join(BASE_DIR, "label_encoders.pkl"))

    print(f"\n✅ Saved:")
    print(f"   {MODEL_PATH}")
    print(f"   {SHAP_PATH}")
    print(f"   {FEAT_PATH}")
    print(f"   {os.path.join(BASE_DIR, 'label_encoders.pkl')}")
