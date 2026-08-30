"""Tests for backend/pcap/zeek_parser.py"""
from backend.pcap.zeek_parser import parse_zeek_dns_log, build_sessions_from_zeek, analyze_zeek_log

SAMPLE_LOG = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\n"
    "1755000000.0\tC1\t192.168.1.10\t50000\t8.8.8.8\t53\tudp\t1234\twww.google.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\n"
    "1755000001.0\tC2\t192.168.1.10\t50001\t8.8.8.8\t53\tudp\t1235\tapi.google.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\n"
)


def test_parse_zeek_dns_log_skips_header_lines():
    records = parse_zeek_dns_log(SAMPLE_LOG)
    assert len(records) == 2
    assert records[0]["query"] == "www.google.com"


def test_parse_zeek_dns_log_handles_empty_input():
    assert parse_zeek_dns_log("") == []


def test_build_sessions_groups_by_client_and_base_domain():
    records = parse_zeek_dns_log(SAMPLE_LOG)
    sessions = build_sessions_from_zeek(records)
    assert len(sessions) == 1  # both queries -> same client, same base domain (google.com)
    assert sessions[0].query_count == 2
    assert sessions[0].client_ip == "192.168.1.10"
    assert sessions[0].base_domain == "google.com"


def test_analyze_zeek_log_returns_expected_shape():
    result = analyze_zeek_log(SAMPLE_LOG)
    assert result["total_dns_records"] == 2
    assert result["sessions_analyzed"] == 1
    assert "results" in result
    assert isinstance(result["tunnel_suspected_sessions"], int)


def test_analyze_zeek_log_handles_empty_log():
    result = analyze_zeek_log("")
    assert result["total_dns_records"] == 0
    assert result["sessions_analyzed"] == 0
    assert result["tunnel_suspected_sessions"] == 0
