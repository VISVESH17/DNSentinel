"""Tests for backend/threat_intelligence/stix_parser.py"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.models import Base, ThreatIndicator
from backend.threat_intelligence.stix_parser import (
    normalize_stix_indicator, parse_bundle, ingest_stix_bundle, _extract_indicator_value,
)


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_extract_domain_pattern():
    result = _extract_indicator_value("[domain-name:value = 'evil.com']")
    assert result == ("evil.com", "domain")


def test_extract_ip_pattern():
    result = _extract_indicator_value("[ipv4-addr:value = '1.2.3.4']")
    assert result == ("1.2.3.4", "ip")


def test_extract_url_pattern_returns_host_only():
    result = _extract_indicator_value("[url:value = 'http://evil.com/payload']")
    assert result == ("evil.com", "domain")


def test_normalize_stix_indicator_skips_non_indicator_objects():
    assert normalize_stix_indicator({"type": "identity", "name": "Some Org"}) is None


def test_normalize_stix_indicator_extracts_fields():
    obj = {
        "type": "indicator",
        "id": "indicator--abc",
        "pattern": "[domain-name:value = 'malicious.example']",
        "indicator_types": ["malicious-activity"],
        "confidence": 90,
        "created_by_ref": "identity--feed",
    }
    normalized = normalize_stix_indicator(obj)
    assert normalized["indicator"] == "malicious.example"
    assert normalized["indicator_type"] == "domain"
    assert normalized["confidence"] == 90
    assert normalized["severity"] == "critical"


def test_parse_bundle_yields_only_valid_indicators():
    bundle = {
        "objects": [
            {"type": "identity", "name": "ignored"},
            {
                "type": "indicator", "id": "indicator--1",
                "pattern": "[domain-name:value = 'a.example']",
                "indicator_types": [], "confidence": 70,
            },
        ]
    }
    results = list(parse_bundle(bundle))
    assert len(results) == 1
    assert results[0]["indicator"] == "a.example"


def test_ingest_stix_bundle_writes_to_db(db_session):
    bundle = {
        "objects": [
            {
                "type": "indicator", "id": "indicator--1",
                "pattern": "[domain-name:value = 'ingest-test.example']",
                "indicator_types": ["malicious-activity"], "confidence": 85,
            },
        ]
    }
    count = ingest_stix_bundle(db_session, bundle)
    assert count == 1

    row = db_session.query(ThreatIndicator).filter(
        ThreatIndicator.indicator == "ingest-test.example"
    ).first()
    assert row is not None
    assert row.confidence == 85
    assert row.source.startswith("STIX:")
