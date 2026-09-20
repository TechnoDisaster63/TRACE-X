import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.m01_eml_parser.parser import parse_eml
from modules.m03_auth_analyzer.analyzer import analyze_authentication

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_legit_email_all_pass():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    r = analyze_authentication(parsed)
    assert r["spf"]["result"] == "pass"
    assert r["dkim"]["result"] == "pass"
    assert r["dmarc"]["result"] == "pass"
    assert r["summary"]["total_findings"] == 0


def test_phishing_email_all_fail():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_authentication(parsed)
    assert r["spf"]["result"] == "fail"
    assert r["dkim"]["result"] == "none"
    assert r["dmarc"]["result"] == "fail"
    sources = {f["source"] for f in r["findings"]}
    assert "auth:spf_fail" in sources
    assert "auth:dmarc_weak" in sources


def test_missing_auth_header():
    parsed = parse_eml(p("malformed/malformed_truncated.eml"))
    r = analyze_authentication(parsed)
    assert r["spf"]["result"] == "none"
    sources = {f["source"] for f in r["findings"]}
    assert "auth:missing_header" in sources


def test_pass_does_not_mean_zero_findings_is_asserted_as_safe():
    """Ensure interpretation text explicitly avoids declaring safety."""
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    r = analyze_authentication(parsed)
    assert "does not confirm" in r["spf"]["interpretation"].lower() or \
           "not confirm" in r["dkim"]["interpretation"].lower()


def test_manipulation_detection():
    parsed = parse_eml(p("edge_cases/auth_anomaly_manipulated.eml"))
    r = analyze_authentication(parsed)
    sources = {f["source"] for f in r["findings"]}
    assert "auth:header_manipulation_suspected" in sources


def test_alignment_mismatch_detected_for_bec():
    parsed = parse_eml(p("bec/bec_ceo_wire_request.eml"))
    r = analyze_authentication(parsed)
    # from domain company.com, auth domain company-support.com -> softfail present
    assert r["spf"]["result"] == "softfail"


def test_findings_have_required_fields():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_authentication(parsed)
    for f in r["findings"]:
        for key in ("finding_id", "finding", "severity", "evidence", "source", "confidence"):
            assert key in f and f[key]
