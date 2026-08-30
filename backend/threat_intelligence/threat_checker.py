"""
Threat Checker -- fast local lookup of a domain against synced threat
indicators. In the full deployment this checks a Redis hot cache first;
for the prototype we query SQLite directly (fast enough at demo scale).
"""
from sqlalchemy.orm import Session

from backend.database.models import ThreatIndicator


def check_domain(db: Session, domain: str) -> ThreatIndicator | None:
    """Return the matching ThreatIndicator row if `domain` is known-bad."""
    return (
        db.query(ThreatIndicator)
        .filter(ThreatIndicator.indicator == domain)
        .first()
    )
