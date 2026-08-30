"""Tests for backend/threat_intelligence/feed_loader.py and threat_checker.py"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.models import Base, ThreatIndicator
from backend.threat_intelligence.threat_checker import check_domain


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_check_domain_returns_none_for_unknown_domain(db_session):
    result = check_domain(db_session, "totally-unknown-domain.com")
    assert result is None


def test_check_domain_finds_matching_indicator(db_session):
    db_session.add(ThreatIndicator(
        indicator="known-bad.com", indicator_type="domain",
        source="test_feed", confidence=90, severity="high",
    ))
    db_session.commit()

    result = check_domain(db_session, "known-bad.com")
    assert result is not None
    assert result.confidence == 90
    assert result.severity == "high"
