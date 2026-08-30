"""
Trains the DGA classifier from data/training_data.csv (columns: domain,label
where label is 1 = malicious/DGA, 0 = benign) and saves it to
backend/ml/model.pkl.

Uses RandomForest by default -- swap in XGBoost (as recommended in the
playbook) once the team has real DGArchive + Tranco data; RandomForest
needs zero extra native dependencies, which keeps `pip install` painless
during the hackathon.

Run with:  python -m backend.ml.train
"""
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from backend.ml.feature_extractor import extract_features, FEATURE_ORDER

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "training_data.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")


def build_feature_dataframe(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    feature_rows = [extract_features(d) for d in df["domain"]]
    features_df = pd.DataFrame(feature_rows)[FEATURE_ORDER]
    features_df["label"] = df["label"].values
    return features_df


def train() -> None:
    df = build_feature_dataframe(DATA_PATH)
    X = df[FEATURE_ORDER]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=10, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("=== DGA Classifier Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    importance = sorted(
        zip(FEATURE_ORDER, model.feature_importances_), key=lambda x: -x[1]
    )
    print("=== Feature importances ===")
    for name, score in importance:
        print(f"  {name:<24} {score:.3f}")

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
