import json
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
from modules.m09_threat_graph.engine import build_threat_graph
from modules.m10_report_generator.engine import generate_report, to_json, to_text

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def _run_full(path, trusted_domains=None):
    parsed = parse_eml(path)
    header_result = analyze_headers(parsed)
    auth_result = analyze_authentication(parsed)
    identity_result = analyze_identity(parsed, trusted_domains=trusted_domains)
    received_result = analyze_received_chain(parsed)
    url_result = analyze_urls(parsed)
    bundle = build_evidence_bundle(header_result, auth_result, identity_result, received_result, url_result)
    risk = compute_risk(bundle)
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    report = generate_report(parsed.to_dict(), bundle, risk, graph)
    return parsed, bundle, risk, graph, report


# ---------------------------------------------------------------------------
# Core structure
# ---------------------------------------------------------------------------

def test_report_has_all_top_level_keys():
    _, _, _, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    for key in ("report_id", "report_version", "generated_at", "email_id",
                "risk_score", "risk_level", "risk_confidence", "threat_class",
                "threat_class_confidence", "header", "executive", "risk_summary",
                "threat_analysis", "evidence_log", "authentication", "indicators",
                "recommendations", "metadata"):
        assert key in report


def test_report_id_unique_across_calls():
    _, bundle_a, risk_a, graph_a, report_a = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    _, bundle_b, risk_b, graph_b, report_b = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    assert report_a["report_id"] != report_b["report_id"]


def test_risk_and_threat_values_consistent_with_upstream():
    parsed, bundle, risk, graph, report = _run_full(p("bec/bec_ceo_wire_request.eml"))
    assert report["risk_score"] == risk["score"]
    assert report["risk_level"] == risk["risk_level"]
    assert report["threat_class"] == graph["threat_class"]


# ---------------------------------------------------------------------------
# Section content
# ---------------------------------------------------------------------------

def test_executive_verdict_mentions_risk_level():
    _, _, risk, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    assert risk["risk_level"] in report["executive"]["verdict"]


def test_risk_summary_has_factors():
    _, _, risk, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    assert len(report["risk_summary"]["risk_factors"]) == len(risk["risk_factors"])


def test_evidence_log_counts_match_bundle():
    _, bundle, _, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    assert report["evidence_log"]["total_items"] == bundle["total_evidence_count"]


def test_indicators_counts_match_graph():
    _, _, _, graph, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    assert report["indicators"]["node_count"] == graph["node_count"]
    assert report["indicators"]["edge_count"] == graph["edge_count"]


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

def test_low_risk_email_has_standard_recommendation():
    _, _, _, _, report = _run_full(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    rule_ids = {r["rule_id"] for r in report["recommendations"]}
    assert "LOW_RISK_STANDARD" in rule_ids


def test_high_or_critical_risk_has_urgent_recommendation():
    _, _, risk, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    if risk["risk_level"] in ("HIGH", "CRITICAL"):
        priorities = [r["priority"] for r in report["recommendations"]]
        assert 1 in priorities


def test_recommendations_sorted_by_priority():
    _, _, _, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    priorities = [r["priority"] for r in report["recommendations"]]
    assert priorities == sorted(priorities)


def test_no_duplicate_recommendation_rules():
    _, _, _, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    rule_ids = [r["rule_id"] for r in report["recommendations"]]
    assert len(rule_ids) == len(set(rule_ids))


def test_recommendation_fields_present():
    _, _, _, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    for rec in report["recommendations"]:
        assert rec["rule_id"]
        assert isinstance(rec["priority"], int)
        assert rec["action"]
        assert rec["rationale"]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_to_json_is_valid_and_matches_report():
    _, _, risk, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    j = to_json(report)
    parsed_json = json.loads(j)
    assert parsed_json["risk_score"] == risk["score"]


def test_to_text_contains_key_sections():
    _, _, _, _, report = _run_full(p("phishing/phishing_paypal_lookalike.eml"))
    text = to_text(report)
    for section in ("TRACE-X ANALYSIS REPORT", "EXECUTIVE SUMMARY", "RISK ASSESSMENT",
                    "THREAT ANALYSIS", "RECOMMENDATIONS", "EVIDENCE LOG", "INDICATORS"):
        assert section in text


def test_to_text_never_raises_on_clean_email():
    _, _, _, _, report = _run_full(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    text = to_text(report)
    assert isinstance(text, str) and len(text) > 100


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_none_inputs_produce_degraded_but_valid_report():
    report = generate_report(None, None, None, None)
    assert report["risk_score"] == 0
    assert report["risk_level"] == "LOW"
    assert isinstance(to_json(report), str)
    assert isinstance(to_text(report), str)


def test_malformed_email_does_not_crash_full_pipeline():
    parsed, bundle, risk, graph, report = _run_full(p("malformed/malformed_empty.eml"))
    assert report is not None
    assert isinstance(to_text(report), str)


def test_all_sample_emails_produce_valid_report():
    samples = [
        "legitimate/legit_newsletter.eml",
        "phishing/phishing_paypal_lookalike.eml",
        "phishing/lookalike_domain.eml",
        "bec/bec_ceo_wire_request.eml",
        "malformed/malformed_truncated.eml",
    ]
    for rel in samples:
        parsed, bundle, risk, graph, report = _run_full(p(rel))
        assert 0 <= report["risk_score"] <= 100
        assert report["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        json.loads(to_json(report))
        assert len(to_text(report)) > 0
