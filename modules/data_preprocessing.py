
import os
import pandas as pd
import numpy as np

INPUT_FILE = "dataset/security_events.csv"
OUTPUT_FILE = "dataset/processed_events.csv"


def preprocess_data():

    print("=" * 60)
    print("       AEGIS-AI DATA PREPROCESSING")
    print("=" * 60)

    # 1. Load dataset
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Dataset not found: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE)

    print("\nOriginal Dataset Shape:", df.shape)

    # 2. Remove duplicate records
    duplicates = df.duplicated().sum()
    df.drop_duplicates(inplace=True)

    print("Duplicates Removed:", duplicates)

    # 3. Handle missing values
    numeric_columns = df.select_dtypes(
        include=[np.number]
    ).columns

    for col in numeric_columns:
        df[col] = df[col].fillna(df[col].median())

    # 4. Handle infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    for col in numeric_columns:
        df[col] = df[col].fillna(df[col].median())

    # 5. Feature Engineering

    # Detect unusual login hours
    df["night_access"] = (
        (df["access_hour"] <= 5) |
        (df["access_hour"] >= 22)
    ).astype(int)

    # Calculate failed login ratio
    df["failed_login_ratio"] = (
        df["failed_logins"] /
        df["login_attempts"].replace(0, 1)
    )

    # Detect unusually large data transfers
    df["high_data_transfer"] = (
        df["data_transfer_mb"] > 500
    ).astype(int)

    # Detect high-risk devices
    df["high_device_risk"] = (
        df["device_risk"] > 75
    ).astype(int)

    # 6. Final validation
    df.replace([np.inf, -np.inf], 0, inplace=True)

    # 7. Save processed dataset
    os.makedirs("dataset", exist_ok=True)

    df.to_csv(OUTPUT_FILE, index=False)

    print("\nProcessed Dataset Shape:", df.shape)

    print("\nNew Engineered Features:")
    print([
        "night_access",
        "failed_login_ratio",
        "high_data_transfer",
        "high_device_risk"
    ])

    print("\nClass Distribution:")
    print(df["event_type"].value_counts())

    print("\nRemaining Missing Values:", df.isnull().sum().sum())

    print("\nProcessed Dataset Saved:", OUTPUT_FILE)

    print("\nTASK 3 COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    preprocess_data()
