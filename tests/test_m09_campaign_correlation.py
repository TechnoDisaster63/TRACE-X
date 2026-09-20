"""
Tests for M09 campaign correlation (correlate_campaign / analyze_campaign).
Uses the existing synthetic test_data/campaign/*.eml (genuinely related)
and mixes in unrelated legitimate/bec/phishing samples to verify no false
correlation occurs.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import analyze_email, analyze_campaign
from modules.m09_threat_graph.engine import correlate_campaign

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_strong_shared_infrastructure_correlates():
    """The 3 synthetic campaign_*.eml samples share sender domain, reply-to
    domain, display name, and URL host -- they must be grouped together."""
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    assert len(files) == 3
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)

    assert len(result["campaigns"]) == 1
    campaign = result["campaigns"][0]
    assert campaign["related_email_count"] == 3
    assert not result["uncorrelated"]
    assert campaign["confidence"] == "HIGH"
    assert campaign["correlation_score"] > 0


def test_shared_urls_are_a_correlation_signal():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    campaign = result["campaigns"][0]
    assert "shared_url_host" in campaign["correlation_signals"]


def test_shared_domain_is_a_correlation_signal():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    campaign = result["campaigns"][0]
    assert "shared_sender_domain" in campaign["correlation_signals"]


def test_shared_sender_identity_display_name_is_a_signal():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    campaign = result["campaigns"][0]
    assert "shared_display_name" in campaign["correlation_signals"]


def test_unrelated_legitimate_emails_not_incorrectly_correlated():
    files = [
        p("legitimate/legit_newsletter.eml"),
        p("bec/bec_ceo_wire_request.eml"),
        p("phishing/lookalike_domain.eml"),
    ]
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    assert result["campaigns"] == []
    assert len(result["uncorrelated"]) == 3


def test_similar_message_pattern_subject_correlation():
    """campaign_01/02/03 have digit-differentiated subjects that normalize
    to different patterns; verify the mechanism doesn't force a false match
    but the OTHER strong signals still correctly group them."""
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    assert len(result["campaigns"]) == 1  # still grouped via domain/url/display-name


def test_single_email_never_forms_a_campaign_alone():
    investigations = [analyze_email(p("phishing/lookalike_domain.eml"))]
    result = correlate_campaign(investigations)
    assert result["campaigns"] == []
    assert result["uncorrelated"] == [investigations[0]["investigation_id"]]


def test_empty_batch_does_not_crash():
    result = correlate_campaign([])
    assert result["campaigns"] == []
    assert result["total_investigations"] == 0


def test_campaign_evidence_is_traceable_and_concrete():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    campaign = result["campaigns"][0]
    assert len(campaign["evidence"]) > 0
    for e in campaign["evidence"]:
        assert isinstance(e, str) and len(e) > 0
    # shared_indicators must contain actual observed values, not booleans
    for indicator_type, values in campaign["shared_indicators"].items():
        assert isinstance(values, list)
        assert all(isinstance(v, str) and v for v in values)


def test_campaign_id_deterministic_for_same_member_set():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    investigations = [analyze_email(f) for f in files]
    r1 = correlate_campaign(investigations)
    r2 = correlate_campaign(investigations)
    assert r1["campaigns"][0]["campaign_id"] == r2["campaigns"][0]["campaign_id"]


def test_analyze_campaign_end_to_end_wires_report_campaign_relationships():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    batch = analyze_campaign(files)
    for inv in batch["investigations"]:
        assert inv["report"]["campaign_relationships"]["is_part_of_campaign"] is True
        assert inv["report"]["campaign_relationships"]["campaign_id"] is not None


def test_analyze_campaign_unrelated_batch_reports_not_in_campaign():
    files = [
        p("legitimate/legit_newsletter.eml"),
        p("bec/bec_ceo_wire_request.eml"),
    ]
    batch = analyze_campaign(files)
    for inv in batch["investigations"]:
        assert inv["report"]["campaign_relationships"]["is_part_of_campaign"] is False


def test_no_campaign_claimed_without_any_shared_indicator():
    """Two emails with completely disjoint identity/url/domain signals must
    never be grouped, even if both happen to be HIGH risk independently."""
    files = [
        p("phishing/lookalike_domain.eml"),          # micros0ft-online.com
        p("phishing/suspicious_url_ip_shortener.eml"),  # bank-secure-notice.com
    ]
    investigations = [analyze_email(f) for f in files]
    result = correlate_campaign(investigations)
    assert result["campaigns"] == []
