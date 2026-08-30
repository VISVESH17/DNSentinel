"""
Threat feed loader.

For the hackathon prototype, feeds are CSV files under /data (see
data/threat_feed.csv and data/malicious_domains.csv). In the full
deployment described in the playbook, this module would instead pull
from STIX/TAXII collections on a background schedule -- the DB layer
underneath is identical either way, which is the point: the live DNS
path never talks to a remote feed directly.
"""
import csv
import os
from datetime import datetime

from sqlalchemy.orm import Session

from backend.database.models import ThreatIndicator

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def load_feed_csv(path: str) -> list[dict]:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def sync_feeds_to_db(db: Session) -> int:
    """Load all CSV feeds in /data into the threat_indicators table.
    Returns the number of indicators inserted or updated."""
    feed_files = ["threat_feed.csv", "malicious_domains.csv"]
    count = 0

    for filename in feed_files:
        path = os.path.join(DATA_DIR, filename)
        for row in load_feed_csv(path):
            indicator_value = row.get("domain") or row.get("indicator")
            if not indicator_value:
                continue

            existing = (
                db.query(ThreatIndicator)
                .filter(ThreatIndicator.indicator == indicator_value)
                .first()
            )
            if existing:
                existing.last_seen = datetime.utcnow()
                existing.confidence = int(row.get("confidence", existing.confidence))
                existing.severity = row.get("severity", existing.severity)
            else:
                db.add(
                    ThreatIndicator(
                        indicator=indicator_value,
                        indicator_type="domain",
                        source=row.get("source", filename),
                        confidence=int(row.get("confidence", 80)),
                        severity=row.get("severity", "high"),
                    )
                )
            count += 1

    db.commit()
    return count
