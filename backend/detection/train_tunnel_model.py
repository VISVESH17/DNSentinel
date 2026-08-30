"""
Generates a synthetic baseline of "normal" DNS session behaviour and
fits the IsolationForest tunnel detector on it, saving the fitted model
to backend/detection/tunnel_model.pkl.

Real deployments would fit this on captured normal traffic (e.g. from
Zeek dns.log over a clean period). For the hackathon prototype we
generate plausible normal sessions so the detector has *something* to
compare against out of the box -- see docs/architecture.md for the
real-data path.

Run with: python -m backend.detection.train_tunnel_model
"""
import os
import random

import joblib

from backend.detection.tunnel_detector import TunnelSession, TunnelAnomalyDetector

MODEL_PATH = os.path.join(os.path.dirname(__file__), "tunnel_model.pkl")


def generate_normal_sessions(n: int = 300) -> list[TunnelSession]:
    random.seed(7)
    sessions = []
    for _ in range(n):
        # Include the full realistic range, including single-query / idle
        # sessions (qpm can legitimately be 0 for a one-off lookup) so the
        # model doesn't treat ordinary low-traffic sessions as anomalous.
        query_count = random.randint(1, 15)
        qpm = 0.0 if query_count == 1 else random.uniform(0.1, 4.0)
        sessions.append(TunnelSession(
            client_ip=f"192.168.1.{random.randint(2, 250)}",
            base_domain=random.choice(["google.com", "office365.com", "cdn-edge.net", "apinode.io"]),
            query_count=query_count,
            unique_subdomains=random.randint(1, min(6, query_count)),
            avg_query_length=random.uniform(3, 20),
            avg_entropy=random.uniform(0.0, 3.0),
            txt_query_ratio=random.uniform(0.0, 0.05),
            nxdomain_ratio=random.uniform(0.0, 0.1),
            avg_bytes_per_query=random.uniform(5, 40),
            queries_per_minute=qpm,
        ))
    return sessions


def train_and_save():
    detector = TunnelAnomalyDetector()
    baseline = generate_normal_sessions()
    detector.fit(baseline)
    joblib.dump(detector.model, MODEL_PATH)
    print(f"Tunnel anomaly model fitted on {len(baseline)} synthetic normal sessions.")
    print(f"Saved to {MODEL_PATH}")


if __name__ == "__main__":
    train_and_save()
