import os

from core.pipeline import analyze_email
from modules.m11_prevention_recommendation.engine import (
    PreventionRecommendation,
    generate_prevention_recommendation,
)

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_clean_message_without_risk_factors_requests_more_analysis():
    result = analyze_email(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    rec = result["prevention"]
    assert rec["recommended_action"] == "REQUEST_ADDITIONAL_ANALYSIS"
    assert rec["action_mode"] == "ADVISORY"
    assert rec["executable"] is False
    assert rec["requires_human_approval"] is False


def test_medium_bec_requires_human_review_without_execution():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    rec = result["prevention"]
    assert rec["recommended_action"] == "REQUIRE_ANALYST_REVIEW"
    assert rec["action_mode"] == "APPROVAL_REQUIRED"
    assert rec["requires_human_approval"] is True
    assert rec["executable"] is False
    assert any("out-of-band" in item for item in rec["counterfactuals"])


def test_high_phishing_recommends_hold_for_review_but_does_not_hold():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    rec = result["prevention"]
    assert rec["recommended_action"] == "HOLD_FOR_REVIEW"
    assert rec["action_mode"] == "APPROVAL_REQUIRED"
    assert "performs no hold" in rec["potential_impact"]
    assert rec["executable"] is False


def test_recommendation_is_traceable_and_explainable():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    rec = result["prevention"]
    assert rec["evidence_ids"]
    assert {e["evidence_id"] for e in rec["explanation"]} == set(rec["evidence_ids"])
    assert all(e["module"] and e["source"] and e["severity"] for e in rec["explanation"])
    assert rec["triggered_rules"]
    assert rec["reason"]
    assert rec["reversibility"]


def test_untrusted_auth_is_disclosed_and_ineligible_for_automation():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    rec = result["prevention"]
    auth_explanations = [e for e in rec["explanation"] if e["module"] == "M03_AUTH_ANALYZER"]
    assert auth_explanations
    assert all(e["automation_eligible"] is False for e in auth_explanations)
    assert any("untrusted source" in item for item in rec["limitations"])


def test_same_inputs_produce_stable_recommendation_id():
    first = analyze_email(p("phishing/lookalike_domain.eml"))
    rec = generate_prevention_recommendation(
        first["investigation_id"], first["evidence"], first["risk"], first["threat_graph"]
    )
    again = generate_prevention_recommendation(
        first["investigation_id"], first["evidence"], first["risk"], first["threat_graph"]
    )
    assert rec["recommendation_id"] == again["recommendation_id"]


def test_missing_context_requests_analysis_not_enforcement():
    rec = generate_prevention_recommendation("TX-EMPTY", {}, {}, {})
    assert rec["recommended_action"] == "REQUEST_ADDITIONAL_ANALYSIS"
    assert rec["evidence_ids"] == []
    assert rec["executable"] is False


def test_typed_model_rejects_executable_recommendation():
    kwargs = dict(
        recommendation_id="REC-X", investigation_id="TX-X", risk_level="HIGH",
        threat_class="PHISHING", recommended_action="HOLD_FOR_REVIEW",
        action_mode="APPROVAL_REQUIRED", confidence="HIGH", evidence_ids=[],
        triggered_rules=[], reason="r", potential_impact="i", reversibility="r",
        policy_ids=[], requires_human_approval=True, created_at="now", executable=True,
    )
    try:
        PreventionRecommendation(**kwargs)
    except ValueError as exc:
        assert "cannot execute" in str(exc)
    else:
        raise AssertionError("executable recommendation was accepted")


def test_m10_report_contains_backward_compatible_prevention_section():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    assert result["report"]["prevention_assessment"] == result["prevention"]
    from modules.m10_report_generator.engine import to_text
    text = to_text(result["report"])
    assert "PREVENTION ASSESSMENT" in text
    assert "Executable              : False" in text


def test_typed_model_rejects_advisory_with_human_approval():
    kwargs = dict(
        recommendation_id="REC-X", investigation_id="TX-X", risk_level="LOW",
        threat_class="UNKNOWN", recommended_action="ALLOW_WITH_NOTICE",
        action_mode="ADVISORY", confidence="LOW", evidence_ids=[],
        triggered_rules=[], reason="r", potential_impact="i", reversibility="r",
        policy_ids=[], requires_human_approval=True, created_at="now", executable=False,
    )
    try:
        PreventionRecommendation(**kwargs)
    except ValueError as exc:
        assert "cannot require human approval" in str(exc)
    else:
        raise AssertionError("inconsistent advisory recommendation was accepted")
