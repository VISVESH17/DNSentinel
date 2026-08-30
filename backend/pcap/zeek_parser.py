"""
Zeek dns.log parser for passive PCAP investigation.

Real deployment: analyst runs `zeek -r capture.pcap` which produces a
tab-separated dns.log. This module parses that log format directly.
Zeek's default dns.log columns (relevant subset):

    ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  trans_id
    query  qclass  qclass_name  qtype  qtype_name  rcode  rcode_name  ...

For the hackathon prototype, since we don't require the team to have
Zeek installed to try the demo, this module also accepts a simplified
CSV format with the same core fields (see data/sample_zeek_dns.log,
written in Zeek's native tab-separated style so it's a drop-in
replacement once the team runs real Zeek).
"""
import csv
import io
from datetime import datetime, timedelta

from backend.detection.tunnel_detector import aggregate_session, TunnelSession


ZEEK_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
               "proto", "trans_id", "query", "qclass", "qclass_name",
               "qtype", "qtype_name", "rcode", "rcode_name"]


def parse_zeek_dns_log(raw_text: str) -> list[dict]:
    """Parses Zeek's tab-separated dns.log format (skipping #-prefixed header
    lines) into a list of query dicts."""
    records = []
    reader = csv.reader(io.StringIO(raw_text), delimiter="\t")
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < len(ZEEK_FIELDS):
            continue
        rec = dict(zip(ZEEK_FIELDS, row))
        records.append(rec)
    return records


def build_sessions_from_zeek(records: list[dict]) -> list[TunnelSession]:
    """Groups parsed Zeek dns.log records by (client, base_domain) and
    aggregates each group into a TunnelSession for the tunnel detector."""
    grouped: dict[tuple, list[dict]] = {}

    for rec in records:
        client_ip = rec.get("id.orig_h", "unknown")
        query = rec.get("query", "")
        qtype = rec.get("qtype_name", "A")
        rcode = rec.get("rcode_name", "NOERROR")

        labels = query.split(".")
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else query
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]

        try:
            ts = datetime.utcfromtimestamp(float(rec.get("ts", 0)))
        except (ValueError, TypeError):
            ts = datetime.utcnow()

        key = (client_ip, base_domain)
        grouped.setdefault(key, []).append({
            "subdomain": subdomain,
            "qtype": qtype,
            "response_code": rcode,
            "timestamp": ts,
            "bytes": len(query),
        })

    sessions = []
    for (client_ip, base_domain), queries in grouped.items():
        sessions.append(aggregate_session(client_ip, base_domain, queries))
    return sessions


def analyze_zeek_log(raw_text: str) -> dict:
    """Full pipeline: parse -> aggregate into sessions -> score each session
    with the tunnel detector. Returns a summary + per-session results."""
    from backend.detection.tunnel_detector import get_fitted_detector

    records = parse_zeek_dns_log(raw_text)
    sessions = build_sessions_from_zeek(records)
    detector = get_fitted_detector()

    results = [detector.score(s) for s in sessions]
    suspected = [r for r in results if r["is_tunnel_suspected"]]

    return {
        "total_dns_records": len(records),
        "sessions_analyzed": len(sessions),
        "tunnel_suspected_sessions": len(suspected),
        "results": results,
    }
