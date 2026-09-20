"""
Tests for the M10 report generator additions made during the M01-M10
correction pass: investigation_id/file propagation, Identity Analysis,
Received Chain, Campaign Relationships, Limitations, and Analyst Notes
sections. Complements (does not replace) tests/test_m10_report_generator.py.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import analyze_email
from modules.m10_report_generator.engine import to_text

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_report_contains_investigation_id_matching_top_level():
    result = analyze_email(p("phishing/lookalike_domain.eml"))
    assert result["report"]["investigation_id"] == result["investigation_id"]
    assert result["report"]["header"]["investigation_id"] == result["investigation_id"]


def test_report_contains_file_name():
    result = analyze_email(p("phishing/lookalike_domain.eml"))
    assert result["report"]["file_name"] == result["file"]
    assert result["report"]["header"]["file_name"] == result["file"]


def test_report_has_identity_analysis_section():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    ident = result["report"]["identity_analysis"]
    assert ident["display_name"]
    assert ident["from_domain"]
    assert isinstance(ident["findings"], list)


def test_report_has_received_chain_section():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    rc = result["report"]["received_chain"]
    assert "hop_count" in rc
    assert "chain" in rc


def test_report_has_limitations_and_analyst_notes():
    result = analyze_email(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    report = result["report"]
    assert len(report["limitations"]) > 0
    assert len(report["analyst_notes"]) > 0
    assert any("prototype" in lim.lower() for lim in report["limitations"])


def test_report_does_not_claim_attacker_identified():
    """Security review requirement: never claim definitive attribution."""
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    full_text = to_text(result["report"])
    assert "attacker identified" not in full_text.lower()


def test_report_default_campaign_relationships_when_analyzed_alone():
    result = analyze_email(p("legitimate/legit_newsletter.eml"))
    camp = result["report"]["campaign_relationships"]
    assert camp["is_part_of_campaign"] is False
    assert camp["campaign_id"] is None


def test_to_text_renders_new_sections_without_crashing():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    text = to_text(result["report"])
    for section in ("IDENTITY ANALYSIS", "RECEIVED CHAIN", "CAMPAIGN RELATIONSHIPS",
                    "LIMITATIONS", "ANALYST NOTES"):
        assert section in text


def test_low_confidence_triggers_analyst_note():
    result = analyze_email(p("edge_cases/multi_received_multi_recipient.eml"))
    if result["risk"]["confidence"] == "LOW":
        notes_text = " ".join(result["report"]["analyst_notes"]).lower()
        assert "indicative" in notes_text or "manual review" in notes_text
