"""Tests for backend/ml/feature_extractor.py and backend/ml/predict.py"""
from backend.ml.feature_extractor import extract_features, features_to_vector, FEATURE_ORDER
from backend.ml.predict import predict_dga_probability


def test_extract_features_returns_all_expected_keys():
    features = extract_features("google.com")
    assert set(features.keys()) == set(FEATURE_ORDER)


def test_features_to_vector_preserves_order():
    features = extract_features("example.com")
    vector = features_to_vector(features)
    assert len(vector) == len(FEATURE_ORDER)
    assert vector[FEATURE_ORDER.index("length")] == features["length"]


def test_random_looking_domain_scores_higher_than_wordlike_domain():
    benign = predict_dga_probability("google.com")
    dga_like = predict_dga_probability("qzx9f2plm7wq1z.xyz")
    assert dga_like["probability"] >= benign["probability"]


def test_predict_returns_expected_shape():
    result = predict_dga_probability("test-domain.com")
    assert "domain" in result
    assert "probability" in result
    assert 0.0 <= result["probability"] <= 1.0
    assert "source" in result
