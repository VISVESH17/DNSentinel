"""
Feed source registry. Tracks where each threat-intelligence feed comes
from, so the dashboard can show provenance (name, type, last sync).
In the full deployment this maps onto the `feed_sources` table and a
real STIX/TAXII client; here it's a static config good enough for a demo.
"""
from datetime import datetime

FEED_SOURCES = [
    {
        "name": "Local Malicious Domains Feed",
        "type": "csv",
        "path": "data/malicious_domains.csv",
        "last_sync": None,
    },
    {
        "name": "Local Threat Feed (phishing/malware/C2)",
        "type": "csv",
        "path": "data/threat_feed.csv",
        "last_sync": None,
    },
    {
        "name": "STIX/TAXII Collection (placeholder)",
        "type": "taxii",
        "path": "https://example-taxii-server/collections/indicators",
        "last_sync": None,
        "note": "Wire up a real TAXII 2.x client here for the full deployment.",
    },
]


def mark_synced(feed_name: str) -> None:
    for feed in FEED_SOURCES:
        if feed["name"] == feed_name:
            feed["last_sync"] = datetime.utcnow().isoformat()
