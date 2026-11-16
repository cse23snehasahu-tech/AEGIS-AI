
import os
import joblib
import pandas as pd
import numpy as np


MODEL_PATH = "models/random_forest_model.pkl"
ISOLATION_PATH = "models/isolation_forest_model.pkl"
FEATURE_PATH = "models/feature_names.pkl"


class AegisThreatDetector:

    def __init__(self):

        if not all(os.path.exists(p) for p in [
            MODEL_PATH, ISOLATION_PATH, FEATURE_PATH
        ]):
            raise FileNotFoundError(
                "Trained model files missing. Complete Task 4."
            )

        self.rf_model = joblib.load(MODEL_PATH)
        self.iso_model = joblib.load(ISOLATION_PATH)
        self.features = joblib.load(FEATURE_PATH)

        print("AEGIS-AI Threat Detection Engine Loaded!")

    def detect_threat(self, event):

        df = pd.DataFrame([event])

        # Validate required features
        missing = [
            feature for feature in self.features
            if feature not in df.columns
        ]

        if missing:
            raise ValueError(
                f"Missing event features: {missing}"
            )

        df = df[self.features].copy()

        if not np.isfinite(df.to_numpy(dtype=float)).all():
            raise ValueError("Event contains invalid numeric values.")

        # Random Forest prediction
        rf_prediction = int(self.rf_model.predict(df)[0])

        rf_probability = float(
            self.rf_model.predict_proba(df)[0][1]
        )

        # Isolation Forest prediction
        iso_prediction = int(
            self.iso_model.predict(df)[0]
        )

        is_anomaly = iso_prediction == -1

        # Combined decision
        is_threat = (
            rf_prediction == 1 or is_anomaly
        )

        if is_threat:
            status = "Suspicious"
        else:
            status = "Normal"

        result = {
            "status": status,
            "is_threat": bool(is_threat),
            "rf_prediction": rf_prediction,
            "rf_probability": round(rf_probability * 100, 2),
            "is_anomaly": bool(is_anomaly),
            "detection_method": "Random Forest + Isolation Forest"
        }

        return result


if __name__ == "__main__":

    detector = AegisThreatDetector()

    test_event = {
        "login_attempts": 10,
        "failed_logins": 8,
        "access_hour": 2,
        "data_transfer_mb": 850,
        "ip_reputation": 8,
        "privilege_level": 3,
        "unusual_location": 1,
        "access_denied": 7,
        "session_duration": 5,
        "device_risk": 95,
        "night_access": 1,
        "failed_login_ratio": 0.8,
        "high_data_transfer": 1,
        "high_device_risk": 1
    }

    result = detector.detect_threat(test_event)

    print("\n" + "=" * 55)
    print("          AEGIS-AI THREAT DETECTION")
    print("=" * 55)

    for key, value in result.items():
        print(f"{key}: {value}")

    print("\nTASK 5 DETECTION TEST COMPLETED!")
