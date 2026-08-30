"""Tests for backend/dns/filter.py and backend/dns/resolver.py"""
from backend.dns.filter import normalize, shannon_entropy
from backend.dns.resolver import resolve, SINKHOLE_IP


def test_normalize_basic_domain():
    result = normalize("Example.COM.")
    assert result.domain == "example.com"
    assert result.tld == "com"
    assert result.subdomain_count == 0


def test_normalize_detects_suspicious_tld():
    result = normalize("free-download.xyz")
    assert result.suspicious_tld is True


def test_normalize_detects_suspicious_keyword():
    result = normalize("secure-paypal-login-verify.xyz")
    assert result.suspicious_keyword is True


def test_normalize_subdomain_count():
    result = normalize("a.b.c.example.com")
    assert result.subdomain_count == 3


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaa") == 0.0


def test_shannon_entropy_increases_with_randomness():
    assert shannon_entropy("qzx9f2plm7") > shannon_entropy("aaaaaaaaaa")


def test_resolve_allow_returns_non_sinkhole_ip():
    result = resolve("example.com", "ALLOW")
    assert result["resolved_ip"] != SINKHOLE_IP
    assert result["response_code"] == "NOERROR"


def test_resolve_block_returns_sinkhole_ip():
    result = resolve("malicious.example", "BLOCK")
    assert result["resolved_ip"] == SINKHOLE_IP
    assert result["response_code"] == "BLOCKED"
