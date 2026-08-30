"""Tests for backend/core/risk_engine.py"""
from backend.core.risk_engine import RiskEvidence, compute_risk


def test_no_evidence_results_in_allow():
    result = compute_risk(RiskEvidence())
    assert result.action == "ALLOW"
    assert result.classification == "SAFE"
    assert result.score == 0.0


def test_threat_intel_hit_pushes_toward_block():
    evidence = RiskEvidence(threat_intel_hit=True, threat_intel_confidence=100)
    result = compute_risk(evidence)
    assert result.score >= 60
    assert result.action in ("ALERT", "BLOCK")


def test_full_evidence_results_in_block():
    evidence = RiskEvidence(
        threat_intel_hit=True, threat_intel_confidence=100,
        dga_probability=1.0, entropy_anomaly=True, tunnel_indicators=True,
    )
    result = compute_risk(evidence)
    assert result.score == 100.0
    assert result.action == "BLOCK"
    assert result.classification == "MALICIOUS"


def test_low_dga_probability_alone_stays_in_monitor_or_allow():
    evidence = RiskEvidence(dga_probability=0.5)
    result = compute_risk(evidence)
    assert result.action in ("ALLOW", "MONITOR")


def test_score_is_clamped_to_100():
    evidence = RiskEvidence(
        threat_intel_hit=True, threat_intel_confidence=100,
        dga_probability=1.0, entropy_anomaly=True, tunnel_indicators=True,
    )
    result = compute_risk(evidence)
    assert result.score <= 100.0
