from datetime import datetime, timezone
import os

import pytest

from core.pipeline import analyze_email
from modules.m12_trust_policy.engine import (
    PolicyValidationError,
    TrustPolicy,
    evaluate_policies,
    validate_policy,
)

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def policy(**overrides):
    base = dict(
        policy_id="POL-001", name="High phishing review", version=1, enabled=True,
        conditions=["risk:HIGH", "threat:PHISHING"], action="ESCALATE_TO_SOC",
        priority=100, requires_approval=True, created_by="security_admin",
    )
    base.update(overrides)
    return base


def context():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    return result["risk"], result["threat_graph"], result["evidence"]


def test_typed_versioned_policy_validation():
    parsed = validate_policy(policy())
    assert isinstance(parsed, TrustPolicy)
    assert parsed.version == 1
    assert parsed.to_dict()["policy_id"] == "POL-001"


@pytest.mark.parametrize("change", [
    {"version": 0}, {"priority": -1}, {"conditions": []},
    {"action": "BLOCK_DOMAIN"}, {"requires_approval": False},
    {"expires_at": "tomorrow"}, {"unexpected": True},
    {"version": True}, {"priority": True}, {"enabled": 1},
    {"requires_approval": "yes"}, {"policy_id": 123},
    {"conditions": ("risk:HIGH",)}, {"metadata": []},
])
def test_invalid_policy_fails_closed(change):
    with pytest.raises(PolicyValidationError):
        validate_policy(policy(**change))


def test_all_conditions_must_match_and_decision_is_explainable():
    risk, graph, evidence = context()
    decision = evaluate_policies([policy()], risk, graph, evidence, "HOLD_FOR_REVIEW",
                                 now=datetime(2026, 9, 20, tzinfo=timezone.utc))
    assert decision["matched_policy_ids"] == ["POL-001"]
    assert decision["evaluations"][0]["matched_conditions"] == ["risk:HIGH", "threat:PHISHING"]
    assert decision["executable"] is False
    assert "No policy action is executed" in decision["explanation"]


def test_expired_and_disabled_policies_do_not_match():
    risk, graph, evidence = context()
    policies = [
        policy(policy_id="EXPIRED", expires_at="2026-09-19T00:00:00+00:00"),
        policy(policy_id="DISABLED", enabled=False),
    ]
    decision = evaluate_policies(policies, risk, graph, evidence, "HOLD_FOR_REVIEW",
                                 now=datetime(2026, 9, 20, tzinfo=timezone.utc))
    assert decision["matched_policy_ids"] == []
    assert decision["effective_action"] == "HOLD_FOR_REVIEW"
    assert {item["reason"] for item in decision["evaluations"]} == {"Policy is expired.", "Policy is disabled."}


def test_higher_priority_wins_deterministically():
    risk, graph, evidence = context()
    policies = [
        policy(policy_id="LOWER", priority=10, action="REQUIRE_ANALYST_REVIEW"),
        policy(policy_id="HIGHER", priority=20, action="ESCALATE_TO_SOC"),
    ]
    decision = evaluate_policies(policies, risk, graph, evidence, "HOLD_FOR_REVIEW")
    assert decision["selected_policy_ids"] == ["HIGHER"]
    assert decision["effective_action"] == "ESCALATE_TO_SOC"
    assert decision["requires_human_approval"] is True


def test_equal_priority_conflict_uses_stronger_review_action():
    risk, graph, evidence = context()
    policies = [
        policy(policy_id="A", action="REQUIRE_ANALYST_REVIEW"),
        policy(policy_id="B", action="ESCALATE_TO_SOC"),
    ]
    decision = evaluate_policies(policies, risk, graph, evidence, "HOLD_FOR_REVIEW")
    assert decision["effective_action"] == "ESCALATE_TO_SOC"
    assert decision["conflict"]["type"] == "EQUAL_PRIORITY_ACTION_CONFLICT"
    assert "NO ACTION EXECUTED" in decision["conflict"]["resolution"]


def test_allow_policy_cannot_weaken_forensic_recommendation():
    risk, graph, evidence = context()
    allow = policy(action="ALLOW_WITH_NOTICE", requires_approval=False)
    decision = evaluate_policies([allow], risk, graph, evidence, "HOLD_FOR_REVIEW")
    assert decision["effective_action"] == "HOLD_FOR_REVIEW"
    assert decision["conflict"]["type"] == "ALLOW_VERSUS_FORENSIC_RISK"


def test_empty_policy_set_uses_advisory_safe_base_default():
    risk, graph, evidence = context()
    decision = evaluate_policies([], risk, graph, evidence, "HOLD_FOR_REVIEW")
    assert decision["default_behavior"] == "BASE_RECOMMENDATION"
    assert decision["effective_action"] == "HOLD_FOR_REVIEW"
    assert decision["executable"] is False


def test_pipeline_m12_policy_can_strengthen_but_not_execute():
    result = analyze_email(
        p("phishing/phishing_paypal_lookalike.eml"),
        policies=[policy()],
    )
    rec = result["prevention"]
    assert rec["recommended_action"] == "ESCALATE_TO_SOC"
    assert rec["policy_ids"] == ["POL-001"]
    assert rec["requires_human_approval"] is True
    assert rec["executable"] is False
    assert rec["policy_decision"]["executable"] is False


def test_duplicate_policy_ids_are_rejected():
    risk, graph, evidence = context()
    with pytest.raises(PolicyValidationError, match="unique"):
        evaluate_policies([policy(), policy()], risk, graph, evidence, "HOLD_FOR_REVIEW")


def test_policy_approval_requirement_is_preserved_for_lower_rank_action():
    risk, graph, evidence = context()
    flagged = policy(action="FLAG_FOR_REVIEW", requires_approval=True)
    decision = evaluate_policies(
        [flagged], risk, graph, evidence, "ALLOW_WITH_NOTICE",
        base_requires_approval=False,
    )
    assert decision["effective_action"] == "FLAG_FOR_REVIEW"
    assert decision["action_mode"] == "APPROVAL_REQUIRED"
    assert decision["requires_human_approval"] is True


def test_base_approval_requirement_cannot_be_weakened():
    risk, graph, evidence = context()
    allow = policy(action="ALLOW_WITH_NOTICE", requires_approval=False)
    decision = evaluate_policies(
        [allow], risk, graph, evidence, "FLAG_FOR_REVIEW",
        base_requires_approval=True,
    )
    assert decision["effective_action"] == "FLAG_FOR_REVIEW"
    assert decision["action_mode"] == "APPROVAL_REQUIRED"
    assert decision["requires_human_approval"] is True
