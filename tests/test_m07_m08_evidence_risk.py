import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.m01_eml_parser.parser import parse_eml
from modules.m02_header_forensics.analyzer import analyze_headers
from modules.m03_auth_analyzer.analyzer import analyze_authentication
from modules.m04_identity_analyzer.analyzer import analyze_identity
from modules.m05_received_chain.analyzer import analyze_received_chain
from modules.m06_url_analyzer.analyzer import analyze_urls
from modules.m07_evidence_engine.engine import build_evidence_bundle
from modules.m08_risk_engine.engine import compute_risk

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def _run_m01_to_m06(path, trusted_domains=None):
    parsed = parse_eml(path)
    header_result = analyze_headers(parsed)
    auth_result = analyze_authentication(parsed)
    identity_result = analyze_identity(parsed, trusted_domains=trusted_domains)
    received_result = analyze_received_chain(parsed)
    url_result = analyze_urls(parsed)
    return header_result, auth_result, identity_result, received_result, url_result


def test_evidence_bundle_has_unique_ids():
    results = _run_m01_to_m06(p("phishing/phishing_paypal_lookalike.eml"))
    bundle = build_evidence_bundle(*results)
    ids = [e["evidence_id"] for e in bundle["evidence"]]
    assert len(ids) == len(set(ids))
    assert bundle["total_evidence_count"] == len(bundle["evidence"])


def test_evidence_bundle_traceable_to_module():
    results = _run_m01_to_m06(p("phishing/phishing_paypal_lookalike.eml"))
    bundle = build_evidence_bundle(*results)
    modules = {e["module"] for e in bundle["evidence"]}
    assert "M03_AUTH_ANALYZER" in modules
    assert "M06_URL_ANALYZER" in modules


def test_evidence_bundle_no_findings_dropped_count():
    results = _run_m01_to_m06(p("phishing/phishing_paypal_lookalike.eml"))
    header_result, auth_result, identity_result, received_result, url_result = results
    raw_total = sum(len(r["findings"]) for r in results)
    bundle = build_evidence_bundle(*results)
    # Bundle count should be <= raw_total (dedup may merge identical pairs), never more
    assert bundle["total_evidence_count"] <= raw_total
    assert bundle["total_evidence_count"] > 0


def test_evidence_bundle_legit_email_low_evidence():
    results = _run_m01_to_m06(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    bundle = build_evidence_bundle(*results)
    assert bundle["severity_counts"]["critical"] == 0
    assert bundle["severity_counts"]["high"] == 0


def test_risk_engine_high_risk_for_phishing():
    results = _run_m01_to_m06(p("phishing/phishing_paypal_lookalike.eml"))
    bundle = build_evidence_bundle(*results)
    risk = compute_risk(bundle)
    assert risk["risk_level"] in ("HIGH", "CRITICAL")
    assert risk["score"] > 0
    assert len(risk["risk_factors"]) > 0


def test_risk_engine_low_risk_for_legit_email():
    results = _run_m01_to_m06(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    bundle = build_evidence_bundle(*results)
    risk = compute_risk(bundle)
    assert risk["risk_level"] == "LOW"
    assert risk["score"] == 0


def test_risk_engine_explanation_and_scoring_method_present():
    results = _run_m01_to_m06(p("bec/bec_ceo_wire_request.eml"))
    bundle = build_evidence_bundle(*results)
    risk = compute_risk(bundle)
    assert risk["explanation"]
    assert "documented" in risk["scoring_method"].lower()


def test_risk_engine_score_bounded_0_100():
    for eml in ["phishing/phishing_paypal_lookalike.eml", "bec/bec_ceo_wire_request.eml",
                "legitimate/legit_newsletter.eml", "phishing/lookalike_domain.eml"]:
        results = _run_m01_to_m06(p(eml))
        bundle = build_evidence_bundle(*results)
        risk = compute_risk(bundle)
        assert 0 <= risk["score"] <= 100


def test_risk_engine_no_arbitrary_weights_all_documented():
    from modules.m08_risk_engine.engine import SEVERITY_WEIGHTS, MAX_CONTRIBUTION_PER_SEVERITY
    assert set(SEVERITY_WEIGHTS.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert set(MAX_CONTRIBUTION_PER_SEVERITY.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
