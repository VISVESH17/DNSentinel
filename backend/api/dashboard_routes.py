"""
Dashboard/statistics API -- powers the SOC-style frontend (frontend/dashboard.html).
"""
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Alert, Detection, DNSQuery, ThreatIndicator

router = APIRouter(prefix="/api/stats", tags=["dashboard"])


@router.get("")
def overview(db: Session = Depends(get_db)):
    total = db.query(DNSQuery).count()
    blocked = db.query(DNSQuery).filter(DNSQuery.action == "BLOCK").count()
    alerted = db.query(DNSQuery).filter(DNSQuery.action == "ALERT").count()
    monitored = db.query(DNSQuery).filter(DNSQuery.action == "MONITOR").count()
    allowed = db.query(DNSQuery).filter(DNSQuery.action == "ALLOW").count()
    indicators = db.query(ThreatIndicator).count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()

    latencies = [r[0] for r in db.query(DNSQuery.latency_ms).all()]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    detector_counts = Counter(
        d.detector_type for d in db.query(Detection.detector_type).all()
    )

    return {
        "total_queries": total,
        "blocked": blocked,
        "alerted": alerted,
        "monitored": monitored,
        "allowed": allowed,
        "threat_indicators": indicators,
        "open_alerts": open_alerts,
        "avg_latency_ms": avg_latency,
        "detections_by_type": dict(detector_counts),
    }


@router.get("/timeline")
def timeline(hours: int = 24, db: Session = Depends(get_db)):
    """Query counts bucketed by hour for the last `hours` hours."""
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = db.query(DNSQuery).filter(DNSQuery.timestamp >= since).all()

    buckets: dict[str, dict[str, int]] = {}
    for r in rows:
        key = r.timestamp.strftime("%Y-%m-%d %H:00")
        buckets.setdefault(key, {"ALLOW": 0, "MONITOR": 0, "ALERT": 0, "BLOCK": 0})
        buckets[key][r.action] = buckets[key].get(r.action, 0) + 1

    return [{"time": k, **v} for k, v in sorted(buckets.items())]


@router.get("/top-domains")
def top_domains(limit: int = 10, db: Session = Depends(get_db)):
    rows = db.query(DNSQuery.domain, DNSQuery.action).all()
    counts = Counter(r.domain for r in rows if r.action == "BLOCK")
    return [{"domain": d, "block_count": c} for d, c in counts.most_common(limit)]


@router.get("/top-clients")
def top_clients(limit: int = 10, db: Session = Depends(get_db)):
    rows = db.query(DNSQuery.client_ip).all()
    counts = Counter(r.client_ip for r in rows)
    return [{"client_ip": ip, "query_count": c} for ip, c in counts.most_common(limit)]
