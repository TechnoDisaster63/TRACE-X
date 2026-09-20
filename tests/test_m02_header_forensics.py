import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.m01_eml_parser.parser import parse_eml
from modules.m02_header_forensics.analyzer import analyze_headers

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def finding_sources(result):
    return {f["source"] for f in result["findings"]}


def test_legit_email_has_no_mismatch_findings():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    result = analyze_headers(parsed)
    sources = finding_sources(result)
    assert "header:reply_to_vs_from" not in sources
    assert "header:return_path_vs_from" not in sources
    assert result["summary"]["total_findings"] == 0


def test_replyto_mismatch_detected():
    parsed = parse_eml(p("phishing/replyto_mismatch.eml"))
    result = analyze_headers(parsed)
    sources = finding_sources(result)
    assert "header:reply_to_vs_from" in sources
    finding = next(f for f in result["findings"] if f["source"] == "header:reply_to_vs_from")
    assert finding["severity"] == "HIGH"
    assert "trustedvendor.com" in finding["evidence"]
    assert "trustedvendor-billing.net" in finding["evidence"]


def test_return_path_mismatch_detected():
    parsed = parse_eml(p("bec/bec_ceo_wire_request.eml"))
    result = analyze_headers(parsed)
    sources = finding_sources(result)
    assert "header:return_path_vs_from" in sources


def test_missing_message_id_flagged():
    parsed = parse_eml(p("malformed/malformed_truncated.eml"))
    result = analyze_headers(parsed)
    sources = finding_sources(result)
    assert "header:message_id_missing" in sources


def test_missing_date_flagged():
    parsed = parse_eml(p("malformed/malformed_truncated.eml"))
    result = analyze_headers(parsed)
    sources = finding_sources(result)
    assert "header:date_missing" in sources


def test_nonstandard_auth_header_flagged():
    parsed = parse_eml(p("edge_cases/auth_anomaly_manipulated.eml"))
    result = analyze_headers(parsed)
    sources = finding_sources(result)
    assert "header:nonstandard_auth_header" in sources


def test_every_finding_has_required_fields():
    parsed = parse_eml(p("phishing/replyto_mismatch.eml"))
    result = analyze_headers(parsed)
    for f in result["findings"]:
        for key in ("finding_id", "finding", "severity", "evidence", "source", "confidence"):
            assert key in f and f[key]


def test_summary_counts_match_findings():
    parsed = parse_eml(p("phishing/replyto_mismatch.eml"))
    result = analyze_headers(parsed)
    total = sum(v for k, v in result["summary"].items() if k != "total_findings")
    assert total == result["summary"]["total_findings"]


def test_empty_email_does_not_crash():
    parsed = parse_eml(p("malformed/malformed_empty.eml"))
    result = analyze_headers(parsed)
    assert "findings" in result
