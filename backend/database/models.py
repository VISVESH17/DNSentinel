"""
SQLAlchemy ORM models for DNSentinel.

Tables mirror the schema from the SIH260003 solution blueprint:
domains, threat_indicators, dns_queries, detections, alerts.
"""
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    risk_score = Column(Float, default=0.0)
    classification = Column(String(50), default="UNKNOWN")  # SAFE / SUSPICIOUS / HIGH_RISK / MALICIOUS
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), index=True, nullable=False)
    indicator_type = Column(String(50), default="domain")  # domain / ip / url
    source = Column(String(100), default="local_feed")
    confidence = Column(Integer, default=80)  # 0-100
    severity = Column(String(20), default="medium")  # low / medium / high / critical
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class DNSQuery(Base):
    __tablename__ = "dns_queries"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    client_ip = Column(String(64), default="127.0.0.1")
    domain = Column(String(255), index=True, nullable=False)
    qtype = Column(String(10), default="A")
    protocol = Column(String(10), default="UDP")
    response_code = Column(String(20), default="NOERROR")
    latency_ms = Column(Float, default=0.0)
    action = Column(String(20), default="ALLOW")  # ALLOW / MONITOR / ALERT / BLOCK
    risk_score = Column(Float, default=0.0)

    detections = relationship("Detection", back_populates="query")


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    query_id = Column(Integer, ForeignKey("dns_queries.id"))
    detector_type = Column(String(50))  # threat_intel / dga_ml / behaviour
    probability = Column(Float, default=0.0)
    reason = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    query = relationship("DNSQuery", back_populates="detections")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), index=True, nullable=False)
    client_ip = Column(String(64), default="127.0.0.1")
    severity = Column(String(20), default="medium")
    alert_type = Column(String(50), default="threat_intel")
    status = Column(String(20), default="open")  # open / investigating / resolved / false_positive
    created_at = Column(DateTime, default=datetime.utcnow)
