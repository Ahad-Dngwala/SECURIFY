import os
import joblib
import pandas as pd
import shap
import numpy as np

# Define the 26 features in exact order as CSV
FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Mean',
    'Packet Length Std', 'Average Packet Size', 'Min Packet Length',
    'Max Packet Length', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'Down/Up Ratio',
    'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean', 'Active Mean',
    'Subflow Fwd Bytes', 'Subflow Bwd Bytes'
]

# Map UI string labels to the CSV Model Actual_Label integers
LABEL_MAP = {
    'normal': 0,
    'http': 1,
    'portscan': 2,
    'ddos': 3,
    'botnet': 4
}

class SecurifyModel:
    _model = None
    _df = None
    _explainer = None
    _shap_cache = {}  # Pre-computed SHAP values per label

    @classmethod
    def load(cls):
        if cls._model is not None and cls._df is not None:
            return
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, 'rf_intrusion_model.pkl')
        csv_path = os.path.join(base_dir, 'test_dataset_predictions.csv')
        
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cls._model = joblib.load(model_path)
            
        cls._df = pd.read_csv(csv_path)
        cls._explainer = shap.TreeExplainer(cls._model)
        
        # ── Pre-warm: compute SHAP on 10 samples per label at startup ──────────
        print("Pre-warming SHAP cache for all 5 labels...")
        for label_name, label_idx in LABEL_MAP.items():
            filtered = cls._df[cls._df['Actual_Label'] == label_idx]
            if len(filtered) == 0:
                continue
            sample_n = min(10, len(filtered))
            sample = filtered.sample(sample_n)
            X_batch = sample[FEATURES]
            shap_vals = cls._explainer.shap_values(X_batch, check_additivity=False)
            # Store as list of (X_row, shap_row) tuples
            cls._shap_cache[label_idx] = []
            for i in range(sample_n):
                cls._shap_cache[label_idx].append({
                    'X': X_batch.iloc[i],
                    'shap': shap_vals[label_idx][i] if isinstance(shap_vals, list) else shap_vals[i, :, label_idx]
                })
            print(f"  [{label_name}] cached {sample_n} samples")
        print("SHAP cache ready — responses will now be instant!")
        
    @classmethod
    def get_simulation(cls, attack_type: str):
        label_mapped = LABEL_MAP.get(attack_type.lower(), 0)
        
        # Use pre-warmed cache for instant response
        if label_mapped in cls._shap_cache and cls._shap_cache[label_mapped]:
            import random
            cached = random.choice(cls._shap_cache[label_mapped])
            X_row = cached['X']
            attributions = np.array(cached['shap'])
            probs = cls._model.predict_proba(X_row.values.reshape(1, -1))[0]
            confidence = probs[label_mapped]
        else:
            # Fallback: live computation
            filtered_df = cls._df[cls._df['Actual_Label'] == label_mapped]
            if len(filtered_df) == 0:
                filtered_df = cls._df
            sampled_row = filtered_df.sample(1)
            X_row = sampled_row[FEATURES].iloc[0]
            X = sampled_row[FEATURES]
            probs = cls._model.predict_proba(X)[0]
            confidence = probs[label_mapped]
            shap_values = cls._explainer.shap_values(X, check_additivity=False)
            if isinstance(shap_values, list):
                attributions = shap_values[label_mapped][0]
            elif len(shap_values.shape) == 3:
                attributions = shap_values[0, :, label_mapped]
            else:
                attributions = shap_values[0]

        factors = []
        abs_attr = np.abs(attributions)
        sum_attr = np.sum(abs_attr)
        if sum_attr == 0: sum_attr = 1.0
        weights = abs_attr / sum_attr
        
        for feat, weight, att in zip(FEATURES, weights, attributions):
            factors.append({
                "label": feat,
                "weight": float(weight),
                "raw_shap": float(att)
            })
            
        factors.sort(key=lambda x: x["weight"], reverse=True)
        
        raw_features = {}
        for f in FEATURES:
            val = float(X_row[f])
            raw_features[f] = int(val) if val.is_integer() else round(val, 2)
        
        return {
            "prediction_class": int(label_mapped),
            "confidence": float(confidence),
            "factors": factors[:5],
            "rawFeatures": raw_features
        }
