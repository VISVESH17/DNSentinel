"""
Loads the trained DGA model (backend/ml/model.pkl) once at import time
and exposes predict_dga_probability(domain) for live inference.

If the model hasn't been trained yet, falls back to a transparent
heuristic (entropy + digit ratio + suspicious TLD) so the API still
works end-to-end before anyone runs `python -m backend.ml.train`.
"""
import os

import joblib
import pandas as pd

from backend.ml.feature_extractor import extract_features, features_to_vector, FEATURE_ORDER

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

_model = None
if os.path.exists(MODEL_PATH):
    _model = joblib.load(MODEL_PATH)


def _heuristic_probability(features: dict) -> float:
    """Simple, explainable fallback used only if no trained model exists yet."""
    score = 0.0
    score += min(0.4, features["entropy"] / 6.0)
    score += min(0.2, features["digit_ratio"])
    score += 0.2 if features["suspicious_tld"] else 0.0
    score += 0.1 if features["hyphen_count"] >= 2 else 0.0
    score += min(0.1, features["length"] / 100.0)
    return round(min(1.0, score), 4)


def predict_dga_probability(domain: str) -> dict:
    features = extract_features(domain)

    if _model is not None:
        vector_df = pd.DataFrame([features_to_vector(features)], columns=FEATURE_ORDER)
        probability = float(_model.predict_proba(vector_df)[0][1])
        source = "trained_model"
    else:
        probability = _heuristic_probability(features)
        source = "heuristic_fallback"

    return {
        "domain": domain,
        "probability": round(probability, 4),
        "source": source,
        "features": features,
    }
