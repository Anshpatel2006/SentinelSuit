import joblib
import json

MODEL_PATH = "models/model.joblib"
SCALER_PATH = "models/scaler.joblib"
FEATURE_PATH = "models/feature_columns.json"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

with open(FEATURE_PATH, "r") as f:
    feature_columns = json.load(f)


def get_model():
    return model


def get_scaler():
    return scaler


def get_feature_columns():
    return feature_columns
