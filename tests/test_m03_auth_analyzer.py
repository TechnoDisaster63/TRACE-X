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


def test_reported_authentication_is_unverified_by_default():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    result = analyze_authentication(parsed)
    assert result["provenance"]["mode"] == "REPORTED_UNVERIFIED"
    assert result["spf"]["result"] == "pass"
    assert result["spf"]["trusted_source"] is False
    assert "not independently verified" in result["provenance"]["warning"]


def test_explicit_authserv_allowlist_marks_matching_header_trusted():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    reported_id = parsed.authentication_results[0].split(";", 1)[0].strip()
    result = analyze_authentication(parsed, trusted_authserv_ids=[reported_id.upper() + "."])
    assert result["provenance"]["mode"] == "TRUSTED_AUTHserv_ID_ALLOWLIST"
    assert result["spf"]["authserv_id"] == reported_id.lower().rstrip(".")
    assert result["spf"]["trusted_source"] is True


def test_nonmatching_authserv_id_remains_untrusted():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    result = analyze_authentication(parsed, trusted_authserv_ids=["trusted.receiver.example"])
    assert result["dkim"]["result"] == "pass"
    assert result["dkim"]["trusted_source"] is False


def test_absent_mechanism_has_no_trusted_source():
    parsed = parse_eml(p("malformed/malformed_truncated.eml"))
    result = analyze_authentication(parsed, trusted_authserv_ids=["mx.example"])
    assert result["dmarc"]["result"] == "none"
    assert result["dmarc"]["authserv_id"] is None
    assert result["dmarc"]["trusted_source"] is False
