"""
Core DNS decision API.

POST /api/dns/check  -- the heart of DNSentinel:
  1. Normalize the incoming domain
  2. Check local threat-intelligence indicators
  3. Run the DGA/ML model
  4. Feed everything into the risk engine
  5. Simulate resolution (ALLOW -> fake IP, BLOCK -> sinkhole)
  6. Log the query + any detections, raise an alert if needed
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.risk_engine import RiskEvidence, compute_risk
from backend.database.database import get_db
from backend.database.models import Alert, Detection, DNSQuery, Domain
from backend.dns.filter import normalize
from backend.dns.resolver import resolve
from backend.ml.predict import predict_dga_probability
from backend.threat_intelligence.threat_checker import check_domain
from backend.utils.logger import get_logger
from backend.utils.validators import is_valid_domain, sanitize_domain

router = APIRouter(prefix="/api/dns", tags=["dns"])
logger = get_logger("dns_routes")


class DNSCheckRequest(BaseModel):
    domain: str
    client_ip: str = "127.0.0.1"
    qtype: str = "A"


class DNSCheckResponse(BaseModel):
    domain: str
    action: str
    classification: str
    risk_score: float
    resolved_ip: str
    latency_ms: float
    reasons: list[str]


@router.post("/check", response_model=DNSCheckResponse)
def check_dns(request: DNSCheckRequest, db: Session = Depends(get_db)):
    domain = sanitize_domain(request.domain)
    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    normalized = normalize(domain)

    # Layer 1: Threat intelligence
    ti_hit = check_domain(db, domain)

    # Layer 2: ML / DGA detection
    ml_result = predict_dga_probability(domain)

    # Layer 3: behavioural / lexical anomaly (entropy proxy for this prototype;
    # a real deployment tracks this per-client over a time window)
    entropy_anomaly = normalized.entropy > 3.5 and normalized.length > 12

    evidence = RiskEvidence(
        threat_intel_hit=ti_hit is not None,
        threat_intel_confidence=ti_hit.confidence if ti_hit else 0,
        dga_probability=ml_result["probability"],
        entropy_anomaly=entropy_anomaly,
        # Live tunnelling detection needs an aggregated (client, domain)
        # session window, not a single query -- see backend/detection/
        # tunnel_detector.py and the passive path at POST /api/pcap/upload,
        # which runs the same detector over a full Zeek dns.log session.
        tunnel_indicators=False,
    )
    risk = compute_risk(evidence)

    # Simulated resolution (sinkhole if blocked)
    resolution = resolve(domain, risk.action)

    # Persist the query
    query_row = DNSQuery(
        client_ip=request.client_ip,
        domain=domain,
        qtype=request.qtype,
        protocol="UDP",
        response_code=resolution["response_code"],
        latency_ms=resolution["latency_ms"],
        action=risk.action,
        risk_score=risk.score,
    )
    db.add(query_row)
    db.flush()  # get query_row.id before commit

    if ti_hit:
        db.add(Detection(
            query_id=query_row.id, detector_type="threat_intel",
            probability=1.0, reason=f"Matched indicator from {ti_hit.source}",
        ))
    if ml_result["probability"] > 0.3:
        db.add(Detection(
            query_id=query_row.id, detector_type="dga_ml",
            probability=ml_result["probability"],
            reason=f"DGA model ({ml_result['source']}) flagged lexical pattern",
        ))

    # Upsert domain reputation record
    domain_row = db.query(Domain).filter(Domain.domain == domain).first()
    if domain_row:
        domain_row.risk_score = risk.score
        domain_row.classification = risk.classification
        from datetime import datetime
        domain_row.last_seen = datetime.utcnow()
    else:
        db.add(Domain(domain=domain, risk_score=risk.score, classification=risk.classification))

    if risk.action in ("ALERT", "BLOCK"):
        db.add(Alert(
            domain=domain,
            client_ip=request.client_ip,
            severity="critical" if risk.action == "BLOCK" else "high",
            alert_type="threat_intel" if ti_hit else "dga_ml",
            status="open",
        ))

    db.commit()

    logger.info(f"{domain} -> {risk.action} (score={risk.score:.1f})")

    return DNSCheckResponse(
        domain=domain,
        action=risk.action,
        classification=risk.classification,
        risk_score=round(risk.score, 2),
        resolved_ip=resolution["resolved_ip"],
        latency_ms=resolution["latency_ms"],
        reasons=risk.reasons,
    )


@router.get("/history")
def dns_history(limit: int = 50, db: Session = Depends(get_db)):
    rows = (
        db.query(DNSQuery)
        .order_by(DNSQuery.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "domain": r.domain,
            "client_ip": r.client_ip,
            "action": r.action,
            "risk_score": r.risk_score,
            "latency_ms": r.latency_ms,
        }
        for r in rows
    ]
