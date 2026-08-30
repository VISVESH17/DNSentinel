"""
Risk Engine — combines Threat Intelligence evidence, ML (DGA) probability
and behavioural signals into a single 0-100 risk score, then maps that
score to a policy decision.

This directly implements the scoring model from the SIH260003 playbook:

    Threat-intelligence match   -> up to +60
    DGA probability             -> up to +20
    High entropy / anomaly      -> up to +10
    Tunnel indicators           -> up to +15

    0-29   SAFE        -> ALLOW
    30-59  SUSPICIOUS   -> MONITOR
    60-79  HIGH_RISK    -> ALERT
    80-100 MALICIOUS    -> BLOCK
"""
from dataclasses import dataclass, field
from typing import List

from backend.core.config import settings


@dataclass
class RiskEvidence:
    """Raw signals collected for one domain lookup, before scoring."""
    threat_intel_hit: bool = False
    threat_intel_confidence: int = 0       # 0-100, from the matched indicator
    dga_probability: float = 0.0           # 0.0-1.0, from the ML model
    entropy_anomaly: bool = False          # unusually high lexical entropy
    tunnel_indicators: bool = False        # behavioural DNS-tunnelling signals
    reasons: List[str] = field(default_factory=list)


@dataclass
class RiskResult:
    score: float
    classification: str   # SAFE / SUSPICIOUS / HIGH_RISK / MALICIOUS
    action: str            # ALLOW / MONITOR / ALERT / BLOCK
    reasons: List[str]


def compute_risk(evidence: RiskEvidence) -> RiskResult:
    score = 0.0
    reasons: List[str] = []

    if evidence.threat_intel_hit:
        ti_contribution = min(60.0, 60.0 * (evidence.threat_intel_confidence / 100.0))
        score += ti_contribution
        reasons.append(
            f"Threat-intel match (confidence={evidence.threat_intel_confidence}) +{ti_contribution:.0f}"
        )

    if evidence.dga_probability > 0:
        dga_contribution = min(20.0, 20.0 * evidence.dga_probability)
        score += dga_contribution
        reasons.append(
            f"DGA/ML probability={evidence.dga_probability:.2f} +{dga_contribution:.0f}"
        )

    if evidence.entropy_anomaly:
        score += 10.0
        reasons.append("High entropy / lexical anomaly +10")

    if evidence.tunnel_indicators:
        score += 15.0
        reasons.append("DNS tunnelling behavioural indicators +15")

    score = max(0.0, min(100.0, score))
    classification, action = _classify(score)
    reasons.extend(evidence.reasons)

    return RiskResult(score=score, classification=classification, action=action, reasons=reasons)


def _classify(score: float) -> tuple[str, str]:
    if score <= settings.risk_allow_max:
        return "SAFE", "ALLOW"
    if score <= settings.risk_monitor_max:
        return "SUSPICIOUS", "MONITOR"
    if score <= settings.risk_alert_max:
        return "HIGH_RISK", "ALERT"
    return "MALICIOUS", "BLOCK"
