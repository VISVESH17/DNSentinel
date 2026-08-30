"""Tests for backend/detection/tunnel_detector.py"""
from datetime import datetime, timedelta

from backend.detection.tunnel_detector import (
    TunnelSession, TunnelAnomalyDetector, aggregate_session, rule_based_flags,
)


def test_rule_based_flags_empty_for_normal_session():
    session = TunnelSession(
        client_ip="192.168.1.5", base_domain="google.com",
        query_count=3, unique_subdomains=2, avg_query_length=10,
        avg_entropy=2.0, txt_query_ratio=0.0, nxdomain_ratio=0.0,
        avg_bytes_per_query=15, queries_per_minute=1.0,
    )
    assert rule_based_flags(session) == []


def test_rule_based_flags_detects_tunnel_pattern():
    session = TunnelSession(
        client_ip="192.168.1.99", base_domain="exfil.example",
        query_count=200, unique_subdomains=180, avg_query_length=52,
        avg_entropy=4.3, txt_query_ratio=0.7, nxdomain_ratio=0.65,
        avg_bytes_per_query=90, queries_per_minute=45,
    )
    flags = rule_based_flags(session)
    assert len(flags) >= 4


def test_detector_cold_start_uses_rule_only():
    detector = TunnelAnomalyDetector()  # unfitted
    tunnel_session = TunnelSession(
        client_ip="1.2.3.4", base_domain="bad.example",
        query_count=100, unique_subdomains=90, avg_query_length=48,
        avg_entropy=4.1, txt_query_ratio=0.6, nxdomain_ratio=0.5,
        avg_bytes_per_query=80, queries_per_minute=30,
    )
    result = detector.score(tunnel_session)
    assert result["source"] == "rule_only_cold_start"
    assert result["is_tunnel_suspected"] is True


def test_aggregate_session_builds_expected_stats():
    now = datetime.utcnow()
    queries = [
        {"subdomain": "abc123", "qtype": "A", "response_code": "NOERROR", "timestamp": now, "bytes": 10},
        {"subdomain": "def456", "qtype": "TXT", "response_code": "NXDOMAIN", "timestamp": now + timedelta(seconds=30), "bytes": 12},
    ]
    session = aggregate_session("10.0.0.5", "example.com", queries)
    assert session.query_count == 2
    assert session.unique_subdomains == 2
    assert session.txt_query_ratio == 0.5
    assert session.nxdomain_ratio == 0.5


def test_aggregate_session_handles_empty_queries():
    session = aggregate_session("10.0.0.5", "example.com", [])
    assert session.query_count == 0
