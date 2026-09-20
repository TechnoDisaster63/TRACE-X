"""
Full M01 -> M08 pipeline integration test, run via core.pipeline.analyze_email
against every synthetic sample in test_data/. Verifies the pipeline never
crashes, always returns a well-formed result, and produces sane risk
classifications for known-legitimate vs known-malicious samples.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import analyze_email

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_pipeline_runs_end_to_end_on_every_sample():
    all_eml = glob.glob(os.path.join(DATA, "**", "*.eml"), recursive=True)
    assert len(all_eml) >= 10, "expected a reasonable number of synthetic samples"
    for path in all_eml:
        result = analyze_email(path)
        # required top-level keys per the integration contract
        for key in ("investigation_id", "file", "file_sha256", "header_forensics",
                    "authentication", "identity", "received_chain", "url_analysis",
                    "evidence", "risk"):
            assert key in result, f"missing key {key} for {path}"
        assert result["risk"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert 0 <= result["risk"]["score"] <= 100


def test_legit_email_scores_low():
    result = analyze_email(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    assert result["risk"]["risk_level"] == "LOW"


def test_phishing_email_scores_high_or_critical():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    assert result["risk"]["risk_level"] in ("HIGH", "CRITICAL")


def test_bec_email_scores_above_low():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    assert result["risk"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_lookalike_domain_scores_high_or_critical():
    result = analyze_email(p("phishing/lookalike_domain.eml"))
    assert result["risk"]["risk_level"] in ("HIGH", "CRITICAL")


def test_multiple_suspicious_indicators_campaign_email():
    result = analyze_email(p("campaign/campaign_01.eml"))
    assert result["risk"]["risk_level"] in ("HIGH", "CRITICAL")
    assert result["evidence"]["total_evidence_count"] >= 3


def test_benign_authentication_anomaly_does_not_falsely_maximize_score():
    """auth_anomaly_manipulated.eml has a manipulation-suspected header but a
    legitimate-looking From/Reply-To/Return-Path; score should reflect the
    header suspicion without hitting the maximum possible score."""
    result = analyze_email(p("edge_cases/auth_anomaly_manipulated.eml"))
    assert result["risk"]["score"] < 100


def test_malformed_email_does_not_crash_pipeline():
    result = analyze_email(p("malformed/malformed_truncated.eml"))
    assert result["risk"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_empty_email_does_not_crash_pipeline():
    result = analyze_email(p("malformed/malformed_empty.eml"))
    assert "risk" in result


def test_evidence_ids_unique_within_single_investigation():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    ids = [e["evidence_id"] for e in result["evidence"]["evidence"]]
    assert len(ids) == len(set(ids))


def test_investigation_ids_increment_across_calls():
    r1 = analyze_email(p("legitimate/legit_newsletter.eml"))
    r2 = analyze_email(p("legitimate/legit_newsletter.eml"))
    assert r1["investigation_id"] != r2["investigation_id"]
