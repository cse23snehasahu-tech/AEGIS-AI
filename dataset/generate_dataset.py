import os
import numpy as np
import pandas as pd

np.random.seed(42)

TOTAL_RECORDS = 10000

def generate_security_dataset(n=TOTAL_RECORDS):

    data = {
        "event_id": range(1, n + 1),
        "login_attempts": np.random.poisson(2, n),
        "failed_logins": np.random.poisson(1, n),
        "access_hour": np.random.randint(0, 24, n),
        "data_transfer_mb": np.random.exponential(100, n),
        "ip_reputation": np.random.uniform(0, 100, n),
        "privilege_level": np.random.choice(
            [0, 1, 2, 3], n,
            p=[0.50, 0.25, 0.20, 0.05]
        ),
        "unusual_location": np.random.choice(
            [0, 1], n, p=[0.90, 0.10]
        ),
        "access_denied": np.random.poisson(1, n),
        "session_duration": np.random.exponential(30, n),
        "device_risk": np.random.uniform(0, 100, n)
    }

    df = pd.DataFrame(data)

    suspicious = (
        (df["failed_logins"] >= 5) |
        (df["ip_reputation"] < 15) |
        (df["unusual_location"] == 1) |
        (df["device_risk"] > 85) |
        (df["access_denied"] >= 5) |
        (df["data_transfer_mb"] > 500)
    )

    df["is_suspicious"] = suspicious.astype(int)

    df["event_type"] = np.where(
        df["is_suspicious"] == 1,
        "Suspicious",
        "Normal"
    )

    return df


if __name__ == "__main__":

    os.makedirs("dataset", exist_ok=True)

    df = generate_security_dataset()

    df.to_csv("dataset/security_events.csv", index=False)

    print("=" * 50)
    print("AEGIS-AI SECURITY DATASET GENERATED")
    print("=" * 50)

    print("Dataset Shape:", df.shape)
    print("\nClass Distribution:")
    print(df["event_type"].value_counts())
    print("\nFirst Five Records:")
    print(df.head())
    print("\nMissing Values:", df.isnull().sum().sum())
    print("\nDataset saved: dataset/security_events.csv")