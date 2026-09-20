from dataclasses import replace

import pytest

from modules.m16_prevention_audit.lifecycle import (
    LifecycleError, create_lifecycle, transition_lifecycle,
    verify_lifecycle_integrity,
)

REC = {
    "recommendation_id": "REC-123", "investigation_id": "TX-123",
    "recommended_action": "HOLD_FOR_REVIEW", "action_mode": "APPROVAL_REQUIRED",
    "requires_human_approval": True, "status": "PENDING", "executable": False,
    "evidence_ids": ["EVID-1"],
}
T0 = "2026-09-20T10:00:00+00:00"
T1 = "2026-09-20T10:01:00+00:00"
T2 = "2026-09-20T10:02:00+00:00"


def created(reversible=True):
    return create_lifecycle(REC, "trace-x", "SYSTEM", T0, reversible=reversible)


def test_create_links_immutable_original_recommendation():
    lifecycle = created()
    assert lifecycle.state == "PENDING"
    assert lifecycle.recommendation_id == REC["recommendation_id"]
    assert lifecycle.events[0].details["recommendation_hash"] == lifecycle.recommendation_hash
    assert verify_lifecycle_integrity(lifecycle, REC)
    assert lifecycle.executes_external_actions is False


def test_legal_review_approval_transitions_are_append_only():
    original = created()
    review = transition_lifecycle(original, "REVIEW_REQUIRED", "alice", "ANALYST", T1, "Needs review")
    approved = transition_lifecycle(review, "APPROVED", "alice", "ANALYST", T2, "Evidence reviewed")
    assert original.state == "PENDING"
    assert len(original.events) == 1
    assert approved.state == "APPROVED"
    assert len(approved.events) == 3
    assert verify_lifecycle_integrity(approved, REC)


@pytest.mark.parametrize("to_state", ["PENDING", "EXECUTED", "REVERSED", "FAILED"])
def test_illegal_direct_transitions_fail(to_state):
    with pytest.raises(LifecycleError, match="illegal transition"):
        transition_lifecycle(created(), to_state, "alice", "ANALYST", T1, "No")


def test_terminal_state_cannot_transition():
    rejected = transition_lifecycle(created(), "REJECTED", "alice", "ANALYST", T1, "False positive")
    with pytest.raises(LifecycleError, match="illegal transition"):
        transition_lifecycle(rejected, "APPROVED", "bob", "SECURITY_ADMIN", T2, "Override")


def test_actor_timestamp_and_reason_required():
    with pytest.raises(LifecycleError, match="actor"):
        create_lifecycle(REC, "", "SYSTEM", T0)
    with pytest.raises(LifecycleError, match="timezone"):
        create_lifecycle(REC, "system", "SYSTEM", "2026-09-20T10:00:00")
    with pytest.raises(LifecycleError, match="reason"):
        transition_lifecycle(created(), "REJECTED", "alice", "ANALYST", T1, "")


def test_execution_state_only_records_external_adapter_outcome():
    approved = transition_lifecycle(created(), "APPROVED", "alice", "ANALYST", T1, "Approved")
    with pytest.raises(LifecycleError, match="ADAPTER"):
        transition_lifecycle(approved, "EXECUTED", "alice", "ANALYST", T2, "Done")
    with pytest.raises(LifecycleError, match="external_action_reference"):
        transition_lifecycle(approved, "EXECUTED", "adapter", "ADAPTER", T2, "Done")
    executed = transition_lifecycle(
        approved, "EXECUTED", "offline-test-adapter", "ADAPTER", T2,
        "Recorded an externally performed outcome; this model did not execute it.",
        {"external_action_reference": "TEST-OUTCOME-1"},
    )
    assert executed.state == "EXECUTED"
    assert executed.executes_external_actions is False


def test_reversal_requires_reversible_flag_and_reference():
    approved = transition_lifecycle(created(), "APPROVED", "alice", "ANALYST", T1, "Approved")
    executed = transition_lifecycle(approved, "EXECUTED", "adapter", "ADAPTER", T2, "Recorded",
                                    {"external_action_reference": "OUT-1"})
    with pytest.raises(LifecycleError, match="reversal_reference"):
        transition_lifecycle(executed, "REVERSED", "bob", "SECURITY_ADMIN",
                             "2026-09-20T10:03:00+00:00", "Reverse")
    reversed_lifecycle = transition_lifecycle(
        executed, "REVERSED", "bob", "SECURITY_ADMIN", "2026-09-20T10:03:00+00:00",
        "External action was reversed.", {"reversal_reference": "REV-1"},
    )
    assert reversed_lifecycle.state == "REVERSED"

    non_reversible = transition_lifecycle(created(False), "APPROVED", "alice", "ANALYST", T1, "Approved")
    non_reversible = transition_lifecycle(non_reversible, "EXECUTED", "adapter", "ADAPTER", T2, "Recorded",
                                          {"external_action_reference": "OUT-2"})
    with pytest.raises(LifecycleError, match="not marked reversible"):
        transition_lifecycle(non_reversible, "REVERSED", "bob", "SECURITY_ADMIN",
                             "2026-09-20T10:03:00+00:00", "Reverse",
                             {"reversal_reference": "REV-2"})


def test_integrity_detects_event_tampering():
    lifecycle = created()
    bad_event = replace(lifecycle.events[0], reason="tampered")
    tampered = replace(lifecycle, events=(bad_event,))
    with pytest.raises(LifecycleError, match="integrity"):
        verify_lifecycle_integrity(tampered)


def test_integrity_detects_original_recommendation_tampering():
    altered = dict(REC, recommended_action="ALLOW_WITH_NOTICE")
    with pytest.raises(LifecycleError, match="original recommendation integrity"):
        verify_lifecycle_integrity(created(), altered)


def test_timestamp_cannot_move_backwards():
    review = transition_lifecycle(created(), "REVIEW_REQUIRED", "alice", "ANALYST", T2, "Review")
    with pytest.raises(LifecycleError, match="precede"):
        transition_lifecycle(review, "REJECTED", "alice", "ANALYST", T1, "Reject")


def test_only_explicitly_non_executable_recommendation_is_accepted():
    with pytest.raises(LifecycleError, match="non-executable"):
        create_lifecycle(dict(REC, executable=True), "system", "SYSTEM", T0)



def test_integrity_rejects_hash_valid_but_illegal_transition_chain():
    """A caller cannot bypass transition validation by constructing frozen models."""
    from modules.m16_prevention_audit import lifecycle as lifecycle_module
    lifecycle = created()
    original = lifecycle.events[0]
    payload = {
        "sequence": 2, "from_state": "PENDING", "to_state": "EXECUTED",
        "actor": "adapter", "actor_role": "ADAPTER", "timestamp": T1,
        "reason": "forged direct execution", "details": {"external_action_reference": "X"},
        "previous_event_hash": original.event_hash,
    }
    forged = lifecycle_module.AuditEvent(
        event_id="AUD-PLACEHOLDER", event_hash="placeholder", **payload
    )
    event_hash = lifecycle_module._digest(payload)
    forged = replace(
        forged, event_hash=event_hash,
        event_id=f"AUD-{event_hash[:16].upper()}",
    )
    tampered = replace(
        lifecycle, state="EXECUTED", updated_at=T1,
        events=(original, forged),
    )
    with pytest.raises(LifecycleError, match="illegal transition"):
        verify_lifecycle_integrity(tampered)


@pytest.mark.parametrize("value", [None, 123, [], {}, object()])
def test_malformed_non_string_timestamp_is_normalized(value):
    with pytest.raises(LifecycleError, match="ISO-8601 string"):
        create_lifecycle(REC, "system", "SYSTEM", value)


def test_equal_timestamps_are_allowed_and_integrity_valid():
    """Ordering comes from sequence/hash links; equal-resolution clocks are valid."""
    review = transition_lifecycle(created(), "REVIEW_REQUIRED", "alice", "ANALYST", T0, "Review")
    approved = transition_lifecycle(review, "APPROVED", "alice", "ANALYST", T0, "Approve")
    assert [event.timestamp for event in approved.events] == [T0, T0, T0]
    assert verify_lifecycle_integrity(approved, REC)


def test_integrity_rejects_non_pending_first_event_even_when_rehashed():
    from modules.m16_prevention_audit import lifecycle as lifecycle_module
    lifecycle = created()
    original = lifecycle.events[0]
    payload = {
        "sequence": 1, "from_state": None, "to_state": "APPROVED",
        "actor": original.actor, "actor_role": original.actor_role,
        "timestamp": original.timestamp, "reason": original.reason,
        "details": original.details, "previous_event_hash": None,
    }
    event_hash = lifecycle_module._digest(payload)
    forged = replace(
        original, to_state="APPROVED", event_hash=event_hash,
        event_id=f"AUD-{event_hash[:16].upper()}",
    )
    tampered = replace(lifecycle, state="APPROVED", events=(forged,))
    with pytest.raises(LifecycleError, match="begin in PENDING"):
        verify_lifecycle_integrity(tampered)
