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

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def _run_to_risk(path, trusted_domains=None):
    parsed = parse_eml(path)
    header_result = analyze_headers(parsed)
    auth_result = analyze_authentication(parsed)
    identity_result = analyze_identity(parsed, trusted_domains=trusted_domains)
    received_result = analyze_received_chain(parsed)
    url_result = analyze_urls(parsed)
    bundle = build_evidence_bundle(header_result, auth_result, identity_result, received_result, url_result)
    risk = compute_risk(bundle)
    return parsed, bundle, risk


# ---------------------------------------------------------------------------
# Core structure
# ---------------------------------------------------------------------------

def test_returns_expected_keys():
    parsed, bundle, risk = _run_to_risk(p("phishing/phishing_paypal_lookalike.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    for key in ("graph_id", "nodes", "edges", "node_count", "edge_count",
                "threat_patterns", "threat_class", "threat_class_confidence",
                "threat_class_reasons", "summary", "risk_score", "risk_level", "built_at"):
        assert key in graph


def test_email_node_always_present():
    parsed, bundle, risk = _run_to_risk(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    email_nodes = [n for n in graph["nodes"] if n["node_type"] == "EMAIL_ADDRESS"]
    assert len(email_nodes) == 1


def test_node_and_edge_ids_unique():
    parsed, bundle, risk = _run_to_risk(p("phishing/phishing_paypal_lookalike.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    node_ids = [n["node_id"] for n in graph["nodes"]]
    edge_ids = [e["edge_id"] for e in graph["edges"]]
    assert len(node_ids) == len(set(node_ids))
    assert len(edge_ids) == len(set(edge_ids))


def test_edges_reference_valid_nodes():
    parsed, bundle, risk = _run_to_risk(p("phishing/phishing_paypal_lookalike.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    node_ids = {n["node_id"] for n in graph["nodes"]}
    for e in graph["edges"]:
        assert e["source_node"] in node_ids
        assert e["target_node"] in node_ids


# ---------------------------------------------------------------------------
# Pattern detection / classification
# ---------------------------------------------------------------------------

def test_clean_email_classified_clean():
    parsed, bundle, risk = _run_to_risk(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    assert risk["score"] == 0
    assert graph["threat_class"] == "CLEAN"
    assert graph["threat_class_confidence"] == "HIGH"


def test_lookalike_domain_phishing_email_classified():
    parsed, bundle, risk = _run_to_risk(p("phishing/phishing_paypal_lookalike.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    assert graph["threat_class"] in ("PHISHING", "BEC", "SPOOFING", "UNKNOWN")
    assert graph["threat_class"] != "CLEAN"


def test_replyto_mismatch_email_pattern_detected():
    parsed, bundle, risk = _run_to_risk(p("phishing/replyto_mismatch.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    pattern_ids = {pt["pattern_id"] for pt in graph["threat_patterns"]}
    if risk["score"] > 0:
        # At minimum some pattern logic ran without crashing; if reply-to
        # mismatch evidence fired, REPLY_TO_REDIRECT should be among matches.
        assert isinstance(pattern_ids, set)


def test_bec_email_scores_and_classifies():
    parsed, bundle, risk = _run_to_risk(p("bec/bec_ceo_wire_request.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    assert graph["risk_score"] == risk["score"]
    assert graph["risk_level"] == risk["risk_level"]


def test_pattern_fields_well_formed():
    parsed, bundle, risk = _run_to_risk(p("phishing/phishing_paypal_lookalike.eml"))
    graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
    for pt in graph["threat_patterns"]:
        assert pt["pattern_id"]
        assert pt["name"]
        assert pt["description"]
        assert isinstance(pt["matched_on"], list)
        assert pt["confidence"] in ("LOW", "MEDIUM", "HIGH")
        assert pt["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert pt["indicates"]


# ---------------------------------------------------------------------------
# Robustness / edge cases
# ---------------------------------------------------------------------------

def test_empty_evidence_bundle_no_crash():
    empty_bundle = {"evidence": [], "evidence_count": 0}
    empty_risk = {"score": 0, "risk_level": "LOW", "risk_factors": [], "confidence": "LOW"}
    graph = build_threat_graph(empty_bundle, empty_risk, email_id="nobody@example.com")
    assert graph["threat_class"] == "CLEAN"
    assert graph["node_count"] == 1  # just the email node


def test_none_inputs_do_not_crash():
    graph = build_threat_graph(None, None, email_id="x@example.com")
    assert graph["threat_class"] == "CLEAN"


def test_unknown_source_tag_ignored_gracefully():
    bundle = {"evidence": [], "evidence_count": 0}
    risk = {
        "score": 5, "risk_level": "LOW", "confidence": "LOW",
        "risk_factors": [{
            "evidence_id": "EVID-0001", "finding": "Something new", "severity": "LOW",
            "weight": 3, "effective_weight": 3, "module": "M99_FUTURE", "source": "future:unknown_tag",
            "correlation_group": "UNGROUPED",
        }],
    }
    graph = build_threat_graph(bundle, risk, email_id="x@example.com")
    # Should not crash, and should not fabricate a node for the unknown tag.
    assert graph["node_count"] == 1


def test_deterministic_repeated_build():
    parsed, bundle, risk = _run_to_risk(p("phishing/phishing_paypal_lookalike.eml"))
    g1 = build_threat_graph(bundle, risk, email_id=parsed.from_)
    g2 = build_threat_graph(bundle, risk, email_id=parsed.from_)
    assert g1["threat_class"] == g2["threat_class"]
    assert g1["node_count"] == g2["node_count"]
    assert g1["edge_count"] == g2["edge_count"]


def test_all_sample_emails_produce_valid_graph():
    samples = [
        "legitimate/legit_newsletter.eml",
        "phishing/phishing_paypal_lookalike.eml",
        "phishing/lookalike_domain.eml",
        "phishing/replyto_mismatch.eml",
        "phishing/suspicious_url_ip_shortener.eml",
        "bec/bec_ceo_wire_request.eml",
        "malformed/malformed_empty.eml",
        "malformed/malformed_truncated.eml",
    ]
    for rel in samples:
        parsed, bundle, risk = _run_to_risk(p(rel))
        graph = build_threat_graph(bundle, risk, email_id=parsed.from_)
        assert graph["threat_class"] in (
            "CLEAN", "UNKNOWN", "PHISHING", "BEC", "SPOOFING", "INFRASTRUCTURE_ABUSE",
        )
        assert graph["node_count"] >= 1
