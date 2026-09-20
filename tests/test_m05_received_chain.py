import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.m01_eml_parser.parser import parse_eml
from modules.m05_received_chain.analyzer import analyze_received_chain

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_multi_hop_chain_ordered_oldest_first():
    parsed = parse_eml(p("edge_cases/multi_received_multi_recipient.eml"))
    r = analyze_received_chain(parsed)
    assert r["hop_count"] == 3
    # Oldest (origin.example.com) should be hop 1 after reversal
    assert r["chain"][0]["hostname"] == "origin.example.com"
    assert r["chain"][-1]["hostname"] == "mx2.example.com"


def test_no_received_headers_flagged():
    parsed = parse_eml(p("malformed/malformed_truncated.eml"))
    r = analyze_received_chain(parsed)
    sources = {f["source"] for f in r["findings"]}
    assert "received:no_hops" in sources
    assert r["hop_count"] == 0


def test_earliest_hop_identified_for_legit_email():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    r = analyze_received_chain(parsed)
    sources = {f["source"] for f in r["findings"]}
    assert "received:earliest_hop_identified" in sources


def test_never_labels_ip_as_attacker():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_received_chain(parsed)
    for f in r["findings"]:
        assert "attacker" not in f["finding"].lower()
        assert "attacker" not in f["evidence"].lower()


def test_ip_extracted_from_received_header():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_received_chain(parsed)
    assert r["chain"][0]["ip"] == "203.0.113.55"


def test_classification_values_valid():
    parsed = parse_eml(p("edge_cases/multi_received_multi_recipient.eml"))
    r = analyze_received_chain(parsed)
    for hop in r["chain"]:
        assert hop["classification"] in ("OBSERVED", "INFERRED", "UNCERTAIN")


def test_findings_have_required_fields():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_received_chain(parsed)
    for f in r["findings"]:
        for key in ("finding_id", "finding", "severity", "evidence", "source", "confidence"):
            assert key in f and f[key]
