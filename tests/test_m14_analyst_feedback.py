from dataclasses import replace
import os

import pytest

from core.pipeline import analyze_email
from modules.m14_analyst_feedback import (
    FeedbackError, create_feedback_record, summarize_feedback, verify_feedback_integrity,
)

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")
TIME = "2026-09-20T18:30:00+00:00"
ALL_DECISIONS = [
    "ACTION_ACCEPTED", "ACTION_REJECTED", "FALSE_POSITIVE", "FALSE_NEGATIVE",
    "TRUSTED_SENDER", "SUSPICIOUS_SENDER_CONFIRMED", "THREAT_ESCALATED",
    "BENIGN_BUSINESS_EMAIL", "NEEDS_MORE_EVIDENCE",
]


def p(rel): return os.path.join(DATA, rel)


def source():
    inv = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    return inv, inv["prevention"]


def make(decision="ACTION_ACCEPTED", **kwargs):
    inv, rec = source()
    params = dict(
        decision_type=decision, actor="analyst-1", actor_role="ANALYST",
        decided_at=TIME, reason="Reviewed original evidence.", investigation=inv,
        recommendation=rec, rule_versions=["M11-1.0", "BEC-1.0"], details={"case": "CASE-1"},
    )
    params.update(kwargs)
    return create_feedback_record(**params), inv, rec


@pytest.mark.parametrize("decision", ALL_DECISIONS)
def test_all_supported_feedback_values(decision):
    record, inv, rec = make(decision)
    assert record.decision_type == decision
    assert verify_feedback_integrity(record, inv, rec)
    assert record.mutates_originals is False
    assert record.executes_actions is False
    assert record.trains_model is False


def test_feedback_preserves_original_objects():
    inv, rec = source()
    before_inv = repr(inv)
    before_rec = repr(rec)
    create_feedback_record(
        "FALSE_POSITIVE", "analyst", "ANALYST", TIME, "Benign business context.",
        inv, rec, rule_versions=["M11-1.0"],
    )
    assert repr(inv) == before_inv
    assert repr(rec) == before_rec


def test_policy_versions_required_when_policies_applied():
    inv, rec = source()
    rec = dict(rec, policy_ids=["POL-1"])
    with pytest.raises(FeedbackError, match="policy_versions"):
        create_feedback_record("ACTION_ACCEPTED", "a", "ANALYST", TIME, "ok", inv, rec,
                               rule_versions=["M11-1.0"])


def test_versions_and_linkage_recorded():
    record, inv, rec = make(policy_versions=["POL-1@v2"], rule_versions=["M11-1.0"])
    assert record.investigation_id == inv["investigation_id"]
    assert record.recommendation_id == rec["recommendation_id"]
    assert record.evidence_ids
    assert record.rule_versions == ("M11-1.0",)
    assert record.policy_versions == ("POL-1@v2",)


def test_integrity_detects_evidence_recommendation_and_record_tampering():
    record, inv, rec = make()
    altered_inv = dict(inv, evidence={"evidence": []})
    with pytest.raises(FeedbackError, match="evidence integrity"):
        verify_feedback_integrity(record, altered_inv, rec)
    with pytest.raises(FeedbackError, match="recommendation integrity"):
        verify_feedback_integrity(record, inv, dict(rec, reason="changed"))
    with pytest.raises(FeedbackError, match="record integrity"):
        verify_feedback_integrity(replace(record, reason="changed"), inv, rec)


def test_recommendation_cannot_reference_foreign_evidence():
    inv, rec = source()
    rec = dict(rec, evidence_ids=[*rec["evidence_ids"], "EVID-FOREIGN"])
    with pytest.raises(FeedbackError, match="outside the investigation"):
        create_feedback_record("ACTION_REJECTED", "a", "ANALYST", TIME, "bad link", inv, rec,
                               rule_versions=["M11-1.0"])


def test_summary_is_review_only_and_deterministic():
    records = [make("FALSE_POSITIVE")[0], make("FALSE_NEGATIVE")[0], make("NEEDS_MORE_EVIDENCE")[0]]
    summary = summarize_feedback(records)
    assert summary == summarize_feedback(records)
    assert summary["record_count"] == 3
    assert len(summary["review_flags"]) == 3
    assert summary["automatic_rule_changes"] is False
    assert summary["automatic_policy_changes"] is False
    assert summary["model_training_performed"] is False
    assert summary["external_actions"] is False


@pytest.mark.parametrize("change", [
    {"decision_type": "LEARN_AUTOMATICALLY"}, {"actor": ""}, {"actor_role": "ADAPTER"},
    {"decided_at": "2026-09-20"}, {"reason": ""}, {"rule_versions": []}, {"details": []},
])
def test_invalid_feedback_fails_closed(change):
    inv, rec = source()
    params = dict(decision_type="ACTION_ACCEPTED", actor="a", actor_role="ANALYST",
                  decided_at=TIME, reason="ok", investigation=inv, recommendation=rec,
                  rule_versions=["M11-1.0"], details={})
    params.update(change)
    with pytest.raises(FeedbackError):
        create_feedback_record(**params)


def test_nested_details_are_deeply_immutable_and_detached_from_input():
    details = {
        "case": {"tags": ["finance", "urgent"], "metadata": {"score": 2}},
        "reviewers": ["alice", "bob"],
    }
    record, inv, rec = make(details=details)
    details["case"]["tags"].append("mutated-after-create")
    details["case"]["metadata"]["score"] = 99
    assert record.details["case"]["tags"] == ("finance", "urgent")
    assert record.details["case"]["metadata"]["score"] == 2
    with pytest.raises(TypeError):
        record.details["new"] = "x"
    with pytest.raises(TypeError):
        record.details["case"]["metadata"]["score"] = 3
    assert verify_feedback_integrity(record, inv, rec)


def test_serialized_details_are_detached_mutable_copies():
    record, inv, rec = make(details={"nested": {"items": [1, 2]}})
    serialized = record.to_dict()
    serialized["details"]["nested"]["items"].append(3)
    assert record.details["nested"]["items"] == (1, 2)
    assert verify_feedback_integrity(record, inv, rec)


def test_unsupported_mutable_detail_type_fails_closed():
    inv, rec = source()
    with pytest.raises(FeedbackError, match="unsupported value type"):
        create_feedback_record(
            "ACTION_ACCEPTED", "a", "ANALYST", TIME, "ok", inv, rec,
            rule_versions=["M11-1.0"], details={"bad": object()},
        )


def test_details_accept_mapping_and_preserve_json_types():
    from types import MappingProxyType

    details = MappingProxyType({"flag": True, "nothing": None, "number": 2.5})
    record, inv, rec = make(details=details)
    assert record.to_dict()["details"] == dict(details)
    assert verify_feedback_integrity(record, inv, rec)


@pytest.mark.parametrize("details, message", [
    ({1: "numeric key"}, "keys must be strings"),
    ({"bad": float("nan")}, "non-finite float"),
    ({"bad": float("inf")}, "non-finite float"),
])
def test_non_json_compatible_details_fail_closed(details, message):
    with pytest.raises(FeedbackError, match=message):
        make(details=details)


def test_set_details_are_canonical_across_insertion_order():
    inv, rec = source()
    args = dict(
        decision_type="ACTION_ACCEPTED", actor="analyst-1", actor_role="ANALYST",
        decided_at=TIME, reason="Reviewed original evidence.", investigation=inv,
        recommendation=rec, rule_versions=["M11-1.0", "BEC-1.0"],
    )
    first = create_feedback_record(**args, details={"tags": {"beta", "alpha"}})
    second = create_feedback_record(**args, details={"tags": {"alpha", "beta"}})
    assert first.record_hash == second.record_hash
    assert first.feedback_id == second.feedback_id
    assert first.to_dict()["details"] == {"tags": ["alpha", "beta"]}
    assert verify_feedback_integrity(first, inv, rec)


def test_recursive_detail_reference_fails_closed():
    details = {}
    details["self"] = details
    with pytest.raises(FeedbackError, match="recursive reference"):
        make(details=details)


def test_reused_non_recursive_alias_is_copied_and_detached():
    shared = {"items": [1]}
    record, inv, rec = make(details={"left": shared, "right": shared})
    shared["items"].append(2)
    assert record.details["left"]["items"] == (1,)
    assert record.details["right"]["items"] == (1,)
    assert verify_feedback_integrity(record, inv, rec)
