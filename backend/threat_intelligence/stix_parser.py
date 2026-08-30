"""
STIX 2.x bundle parser.

Implements the "Ingestion pipeline" from the SIH260003 playbook:

    TAXII collection -> background worker -> STIX parser -> IOC
    normalization -> PostgreSQL -> Redis hot cache -> live DNS correlation

For the hackathon prototype there's no live TAXII server to poll, so
this module parses STIX 2.x JSON bundles from local files (see
data/stix_sample_bundle.json) using the same normalization logic a real
TAXII client would feed into. Swap `load_bundle_from_file` for a real
taxii2-client `as_pages()` poll once the team has a collection URL and
credentials -- everything downstream (normalize_stix_indicator,
DB upsert) stays the same.
"""
import json
import re
from datetime import datetime
from typing import Iterator

from sqlalchemy.orm import Session

from backend.database.models import ThreatIndicator

# STIX pattern examples we can extract from:
#   [domain-name:value = 'evil.com']
#   [ipv4-addr:value = '1.2.3.4']
#   [url:value = 'http://evil.com/payload']
_DOMAIN_PATTERN = re.compile(r"domain-name:value\s*=\s*'([^']+)'")
_IP_PATTERN = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'")
_URL_PATTERN = re.compile(r"url:value\s*=\s*'([^']+)'")


def _extract_indicator_value(stix_pattern: str) -> tuple[str, str] | None:
    """Returns (value, type) extracted from a STIX pattern string, or None."""
    if m := _DOMAIN_PATTERN.search(stix_pattern):
        return m.group(1), "domain"
    if m := _IP_PATTERN.search(stix_pattern):
        return m.group(1), "ip"
    if m := _URL_PATTERN.search(stix_pattern):
        # extract just the domain/host from the URL for DNS correlation
        host = re.sub(r"^https?://", "", m.group(1)).split("/")[0]
        return host, "domain"
    return None


_SEVERITY_MAP = {
    "high": "critical", "medium": "high", "low": "medium",
}


def normalize_stix_indicator(stix_object: dict) -> dict | None:
    """Converts a single STIX 2.x `indicator` SDO into our normalized dict shape."""
    if stix_object.get("type") != "indicator":
        return None

    extracted = _extract_indicator_value(stix_object.get("pattern", ""))
    if not extracted:
        return None
    value, ind_type = extracted

    labels = stix_object.get("indicator_types", stix_object.get("labels", []))
    confidence = stix_object.get("confidence", 75)  # STIX confidence is 0-100 already

    severity = "high"
    if "malicious-activity" in labels or "malware" in labels:
        severity = "critical"
    elif "anomalous-activity" in labels:
        severity = "medium"

    return {
        "indicator": value,
        "indicator_type": ind_type,
        "source": stix_object.get("created_by_ref", "stix_bundle"),
        "confidence": int(confidence),
        "severity": severity,
        "stix_id": stix_object.get("id", ""),
        "malware_family": ", ".join(labels) if labels else None,
        "first_seen": stix_object.get("valid_from"),
    }


def parse_bundle(bundle: dict) -> Iterator[dict]:
    """Yields normalized indicator dicts from a STIX 2.x bundle."""
    for obj in bundle.get("objects", []):
        normalized = normalize_stix_indicator(obj)
        if normalized:
            yield normalized


def load_bundle_from_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ingest_stix_bundle(db: Session, bundle: dict) -> int:
    """Normalizes and upserts every indicator SDO in a STIX bundle into
    the threat_indicators table. Returns count ingested."""
    count = 0
    for indicator in parse_bundle(bundle):
        existing = (
            db.query(ThreatIndicator)
            .filter(ThreatIndicator.indicator == indicator["indicator"])
            .first()
        )
        if existing:
            existing.confidence = indicator["confidence"]
            existing.severity = indicator["severity"]
            existing.last_seen = datetime.utcnow()
        else:
            db.add(ThreatIndicator(
                indicator=indicator["indicator"],
                indicator_type=indicator["indicator_type"],
                source=f"STIX:{indicator['source']}",
                confidence=indicator["confidence"],
                severity=indicator["severity"],
            ))
        count += 1

    db.commit()
    return count
