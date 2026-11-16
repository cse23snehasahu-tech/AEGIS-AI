
import os
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)

INPUT_FILE = "dataset/processed_events.csv"
MODEL_DIR = "models"
REPORT_DIR = "reports"

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def train_models():

    print("=" * 65)
    print("          AEGIS-AI MACHINE LEARNING TRAINING")
    print("=" * 65)

    # 1. Load processed dataset
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            "Processed dataset missing. Complete Task 3 first."
        )

    df = pd.read_csv(INPUT_FILE)

    print("\nDataset Loaded:", df.shape)

    # 2. Select features and target
    excluded_columns = [
        "event_id",
        "is_suspicious",
        "event_type"
    ]

    X = df.drop(columns=excluded_columns)
    y = df["is_suspicious"]

    feature_names = list(X.columns)

    print("\nFeature Count:", len(feature_names))
    print("Target Distribution:")
    print(y.value_counts())

    # 3. Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\nTraining Records:", len(X_train))
    print("Testing Records:", len(X_test))

    # 4. Train Random Forest Classifier
    print("\nTraining Random Forest Classifier...")

    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    rf_model.fit(X_train, y_train)

    # 5. Evaluate Random Forest
    predictions = rf_model.predict(X_test)
    probabilities = rf_model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, zero_division=0
    )
    auc = roc_auc_score(y_test, probabilities)

    print("\nRANDOM FOREST RESULTS")
    print("-" * 45)
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"ROC-AUC   : {auc:.4f}")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Suspicious"],
        zero_division=0
    ))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # 6. Train Isolation Forest on normal training events
    print("\nTraining Isolation Forest...")

    normal_training_data = X_train[
        y_train == 0
    ]

    isolation_model = IsolationForest(
        n_estimators=150,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )

    isolation_model.fit(normal_training_data)

    isolation_predictions = isolation_model.predict(X_test)

    # Isolation Forest: -1 = anomaly, 1 = normal
    anomaly_predictions = (
        isolation_predictions == -1
    ).astype(int)

    anomaly_count = int(anomaly_predictions.sum())

    print("\nISOLATION FOREST RESULTS")
    print("-" * 45)
    print("Anomalies Detected:", anomaly_count)
    print("Normal Events:", len(X_test) - anomaly_count)

    iso_f1 = f1_score(
        y_test,
        anomaly_predictions,
        zero_division=0
    )

    print("Anomaly Detection F1:", round(iso_f1, 4))

    # 7. Save models and feature names
    joblib.dump(
        rf_model,
        os.path.join(MODEL_DIR, "random_forest_model.pkl")
    )

    joblib.dump(
        isolation_model,
        os.path.join(MODEL_DIR, "isolation_forest_model.pkl")
    )

    joblib.dump(
        feature_names,
        os.path.join(MODEL_DIR, "feature_names.pkl")
    )

    # 8. Save evaluation metrics
    metrics = {
        "Model": [
            "Random Forest",
            "Isolation Forest"
        ],
        "Accuracy": [
            accuracy,
            np.nan
        ],
        "Precision": [
            precision,
            precision_score(
                y_test, anomaly_predictions,
                zero_division=0
            )
        ],
        "Recall": [
            recall,
            recall_score(
                y_test, anomaly_predictions,
                zero_division=0
            )
        ],
        "F1 Score": [
            f1,
            iso_f1
        ],
        "ROC_AUC": [
            auc,
            np.nan
        ]
    }

    metrics_df = pd.DataFrame(metrics)

    metrics_df.to_csv(
        os.path.join(REPORT_DIR, "model_metrics.csv"),
        index=False
    )

    # 9. Save feature importance
    importance_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": rf_model.feature_importances_
    }).sort_values(
        by="Importance",
        ascending=False
    )

    importance_df.to_csv(
        os.path.join(REPORT_DIR, "feature_importance.csv"),
        index=False
    )

    # 10. Final verification
    print("\nMODEL FILES SAVED:")

    print("1. models/random_forest_model.pkl")
    print("2. models/isolation_forest_model.pkl")
    print("3. models/feature_names.pkl")
    print("4. reports/model_metrics.csv")
    print("5. reports/feature_importance.csv")

    print("\nTop 5 Important Features:")
    print(importance_df.head())

    print("\nTASK 4 COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    train_models()
