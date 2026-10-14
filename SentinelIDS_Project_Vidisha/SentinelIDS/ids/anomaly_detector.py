import json
from pathlib import Path

import joblib
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE / "models"

PROTOCOL_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "TLS": 6,
    "ARP": 0
}

DROP_COLUMNS = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Source Port"
]


class AnomalyDetector:

    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = []
        self.load_model()

    def load_model(self):
        model_path = MODEL_DIR / "model.joblib"
        scaler_path = MODEL_DIR / "scaler.joblib"
        feature_path = MODEL_DIR / "feature_columns.json"

        print("[ML] Loading model...")

        if model_path.exists():
            self.model = joblib.load(model_path)

        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)

        if feature_path.exists():
            with open(feature_path, "r") as f:
                self.feature_columns = json.load(f)

        print("[ML] Model Loaded :", self.model is not None)
        print("[ML] Scaler Loaded :", self.scaler is not None)
        print("[ML] Features Loaded :", len(self.feature_columns) > 0)

    def model_ready(self):
        return (
            self.model is not None
            and self.scaler is not None
            and len(self.feature_columns) > 0
        )

    def prepare_features(self, feature_dict):
        row = feature_dict.copy()

        if "Protocol" in row:
            row["Protocol"] = PROTOCOL_MAP.get(
                str(row["Protocol"]).upper(),
                255
            )

        for col in DROP_COLUMNS:
            row.pop(col, None)

        df = pd.DataFrame([row])
        df = df.reindex(columns=self.feature_columns, fill_value=0)
        df = df.fillna(0)

        return df

    def predict(self, feature_dict):
        if not self.model_ready():
            return {
                "status": "MODEL_NOT_AVAILABLE",
                "prediction": "BENIGN",
                "confidence": 0.0
            }

        try:
            df = self.prepare_features(feature_dict)
            scaled = self.scaler.transform(df)

            prediction = self.model.predict(scaled)[0]

            confidence = 100.0
            if hasattr(self.model, "predict_proba"):
                probability = self.model.predict_proba(scaled)[0]
                confidence = round(float(max(probability) * 100), 2)

            return {
                "status": "SUCCESS",
                "prediction": prediction,
                "confidence": confidence
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "prediction": "BENIGN",
                "confidence": 0.0,
                "error": str(e)
            }


detector = AnomalyDetector()


if __name__ == "__main__":
    print("\nModel Ready :", detector.model_ready())

    sample = {
        "Destination Port": 80,
        "Protocol": "TCP",
        "Flow Duration": 1000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5
    }

    print("\nSample Prediction")
    print(detector.predict(sample))
