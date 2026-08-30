"""
DNS Tunnelling Detection -- hybrid detector combining a threshold/rule
layer with unsupervised anomaly detection (Isolation Forest), per the
SIH260003 playbook's "DNS tunnelling -- hybrid detector" design.

DNS tunnelling encodes data (exfiltration, C2) inside DNS queries --
typically TXT/NULL records, unusually long or high-entropy subdomains,
and abnormal query volume/frequency to a single domain. Any one query
rarely looks obviously malicious; the signal is behavioural and shows
up when you aggregate queries per (client, domain) over a time window.

This module works on aggregated "sessions" -- see aggregate_session()
-- rather than single queries, matching how the playbook says to treat
this detector.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.dns.filter import shannon_entropy


@dataclass
class TunnelSession:
    """Aggregated behaviour for one (client_ip, base_domain) pair over a window."""
    client_ip: str
    base_domain: str
    query_count: int = 0
    unique_subdomains: int = 0
    avg_query_length: float = 0.0
    avg_entropy: float = 0.0
    txt_query_ratio: float = 0.0
    nxdomain_ratio: float = 0.0
    avg_bytes_per_query: float = 0.0
    queries_per_minute: float = 0.0


SESSION_FEATURE_ORDER = [
    "query_count", "unique_subdomains", "avg_query_length", "avg_entropy",
    "txt_query_ratio", "nxdomain_ratio", "avg_bytes_per_query", "queries_per_minute",
]


# Rule/threshold layer -- obvious, explainable indicators that don't need ML
RULE_THRESHOLDS = {
    "unique_subdomains": 40,       # many distinct subdomains to one base domain
    "avg_query_length": 45,        # unusually long queries (data encoded in labels)
    "avg_entropy": 3.8,            # high per-label entropy (base32/base64-like payloads)
    "txt_query_ratio": 0.5,        # heavy use of TXT records (common exfil channel)
    "nxdomain_ratio": 0.6,         # lots of NXDOMAIN (probing / beaconing pattern)
    "queries_per_minute": 20,      # high query rate to one domain
}


def session_to_vector(session: TunnelSession) -> List[float]:
    return [getattr(session, f) for f in SESSION_FEATURE_ORDER]


def rule_based_flags(session: TunnelSession) -> List[str]:
    """Explainable threshold checks -- always run, cheap, catches obvious cases."""
    flags = []
    if session.unique_subdomains >= RULE_THRESHOLDS["unique_subdomains"]:
        flags.append(f"High unique-subdomain count ({session.unique_subdomains})")
    if session.avg_query_length >= RULE_THRESHOLDS["avg_query_length"]:
        flags.append(f"Abnormally long queries (avg {session.avg_query_length:.0f} chars)")
    if session.avg_entropy >= RULE_THRESHOLDS["avg_entropy"]:
        flags.append(f"High label entropy (avg {session.avg_entropy:.2f})")
    if session.txt_query_ratio >= RULE_THRESHOLDS["txt_query_ratio"]:
        flags.append(f"Heavy TXT record usage ({session.txt_query_ratio:.0%})")
    if session.nxdomain_ratio >= RULE_THRESHOLDS["nxdomain_ratio"]:
        flags.append(f"High NXDOMAIN ratio ({session.nxdomain_ratio:.0%})")
    if session.queries_per_minute >= RULE_THRESHOLDS["queries_per_minute"]:
        flags.append(f"High query rate ({session.queries_per_minute:.1f}/min)")
    return flags


class TunnelAnomalyDetector:
    """Wraps an IsolationForest fitted on a baseline of normal session behaviour.
    Falls back to rule-only detection if not yet fitted (cold start)."""

    def __init__(self):
        self.model: IsolationForest | None = None

    def fit(self, baseline_sessions: List[TunnelSession]) -> None:
        if len(baseline_sessions) < 10:
            return  # not enough data to fit meaningfully
        X = np.array([session_to_vector(s) for s in baseline_sessions])
        self.model = IsolationForest(
            n_estimators=150, contamination=0.05, random_state=42
        )
        self.model.fit(X)

    def score(self, session: TunnelSession) -> dict:
        rule_flags = rule_based_flags(session)

        if self.model is not None:
            vector = np.array([session_to_vector(session)])
            # decision_function: higher = more normal, lower/negative = more anomalous
            raw = self.model.decision_function(vector)[0]
            is_anomaly = self.model.predict(vector)[0] == -1
            # normalize raw score into a rough 0-1 anomaly probability for display
            anomaly_probability = round(max(0.0, min(1.0, 0.5 - raw)), 4)
            source = "isolation_forest"
            # Require the ML anomaly signal to be corroborated by at least one
            # explainable rule flag before calling it tunnel-suspected -- an
            # isolated ML-only flag on ordinary low-traffic sessions is too
            # noisy to act on alone (see docs/architecture.md).
            suspected = is_anomaly and len(rule_flags) >= 1
        else:
            is_anomaly = len(rule_flags) >= 2
            anomaly_probability = min(1.0, len(rule_flags) * 0.25)
            source = "rule_only_cold_start"
            suspected = is_anomaly

        return {
            "client_ip": session.client_ip,
            "base_domain": session.base_domain,
            "is_tunnel_suspected": bool(suspected or len(rule_flags) >= 2),
            "anomaly_probability": anomaly_probability,
            "rule_flags": rule_flags,
            "source": source,
        }


def aggregate_session(client_ip: str, base_domain: str, queries: List[dict]) -> TunnelSession:
    """Build a TunnelSession from a list of raw query dicts:
    {"subdomain": str, "qtype": str, "response_code": str, "timestamp": datetime, "bytes": int}
    """
    if not queries:
        return TunnelSession(client_ip=client_ip, base_domain=base_domain)

    subdomains = {q["subdomain"] for q in queries}
    lengths = [len(q["subdomain"]) for q in queries]
    entropies = [shannon_entropy(q["subdomain"]) for q in queries]
    txt_count = sum(1 for q in queries if q.get("qtype") == "TXT")
    nx_count = sum(1 for q in queries if q.get("response_code") == "NXDOMAIN")
    byte_sizes = [q.get("bytes", len(q["subdomain"])) for q in queries]

    timestamps = sorted(q["timestamp"] for q in queries if q.get("timestamp"))
    if len(timestamps) >= 2:
        span_minutes = max(0.01, (timestamps[-1] - timestamps[0]).total_seconds() / 60.0)
        qpm = len(queries) / span_minutes
    else:
        qpm = 0.0

    return TunnelSession(
        client_ip=client_ip,
        base_domain=base_domain,
        query_count=len(queries),
        unique_subdomains=len(subdomains),
        avg_query_length=sum(lengths) / len(lengths),
        avg_entropy=sum(entropies) / len(entropies),
        txt_query_ratio=txt_count / len(queries),
        nxdomain_ratio=nx_count / len(queries),
        avg_bytes_per_query=sum(byte_sizes) / len(byte_sizes),
        queries_per_minute=qpm,
    )


def get_fitted_detector() -> TunnelAnomalyDetector:
    """Loads the pre-trained IsolationForest (backend/detection/tunnel_model.pkl)
    if it exists; otherwise returns an unfitted detector that falls back to
    rule-only detection. Run `python -m backend.detection.train_tunnel_model`
    to generate the model file."""
    import os
    import joblib

    detector = TunnelAnomalyDetector()
    model_path = os.path.join(os.path.dirname(__file__), "tunnel_model.pkl")
    if os.path.exists(model_path):
        detector.model = joblib.load(model_path)
    return detector
