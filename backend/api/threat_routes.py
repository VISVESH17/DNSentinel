"""
Threat-intelligence API: feed sync + indicator lookups.
"""
import os

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.auth.security import require_role
from backend.database.database import get_db
from backend.database.models import ThreatIndicator
from backend.threat_intelligence.feed_loader import sync_feeds_to_db
from backend.threat_intelligence.feeds import FEED_SOURCES
from backend.threat_intelligence.stix_parser import ingest_stix_bundle, load_bundle_from_file
from backend.utils.logger import get_logger

router = APIRouter(prefix="/api/threat", tags=["threat-intelligence"])
logger = get_logger("threat_routes")

STIX_SAMPLE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "stix_sample_bundle.json"
)


@router.post("/feeds/sync")
def sync_feeds(db: Session = Depends(get_db), user=Depends(require_role("admin", "analyst"))):
    """Sync local CSV feeds (admin/analyst only)."""
    count = sync_feeds_to_db(db)
    logger.info(f"Synced {count} threat indicators from local feeds (by {user.username})")
    return {"synced_indicators": count, "sources": [f["name"] for f in FEED_SOURCES if f["type"] == "csv"]}


@router.post("/feeds/sync-stix")
def sync_stix(db: Session = Depends(get_db), user=Depends(require_role("admin", "analyst"))):
    """Ingest the sample STIX 2.x bundle (admin/analyst only).
    In the full deployment this polls a real TAXII 2.x collection on a
    schedule -- see backend/threat_intelligence/stix_parser.py."""
    bundle = load_bundle_from_file(STIX_SAMPLE_PATH)
    count = ingest_stix_bundle(db, bundle)
    logger.info(f"Ingested {count} STIX indicators (by {user.username})")
    return {"ingested_indicators": count, "bundle_id": bundle.get("id")}


@router.get("/sources")
def list_sources():
    return FEED_SOURCES


@router.get("/indicators")
def list_indicators(limit: int = 100, db: Session = Depends(get_db)):
    rows = db.query(ThreatIndicator).limit(limit).all()
    return [
        {
            "id": r.id,
            "indicator": r.indicator,
            "type": r.indicator_type,
            "source": r.source,
            "confidence": r.confidence,
            "severity": r.severity,
            "last_seen": r.last_seen.isoformat(),
        }
        for r in rows
    ]


@router.get("/domain/{domain}")
def get_domain_threat(domain: str, db: Session = Depends(get_db)):
    row = db.query(ThreatIndicator).filter(ThreatIndicator.indicator == domain).first()
    if not row:
        return {"domain": domain, "known_threat": False}
    return {
        "domain": domain,
        "known_threat": True,
        "source": row.source,
        "confidence": row.confidence,
        "severity": row.severity,
    }
