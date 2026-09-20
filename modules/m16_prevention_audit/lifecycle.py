"""M16 - immutable offline prevention audit and action lifecycle.

The model records decisions; it cannot perform an external action. Every
transition returns a new frozen lifecycle with an append-only hash-linked
event tuple and immutable linkage to the original recommendation snapshot.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


class LifecycleError(ValueError):
    """Lifecycle input, transition, or integrity is invalid."""


STATES = {
    "PENDING", "REVIEW_REQUIRED", "APPROVED", "REJECTED", "EXECUTED",
    "FAILED", "EXPIRED", "REVERSED", "CANCELLED",
}
TRANSITIONS = {
    "PENDING": {"REVIEW_REQUIRED", "APPROVED", "REJECTED", "EXPIRED", "CANCELLED"},
    "REVIEW_REQUIRED": {"APPROVED", "REJECTED", "EXPIRED", "CANCELLED"},
    "APPROVED": {"EXECUTED", "FAILED", "EXPIRED", "CANCELLED"},
    "EXECUTED": {"REVERSED"},
    "FAILED": set(),
    "REJECTED": set(),
    "EXPIRED": set(),
    "REVERSED": set(),
    "CANCELLED": set(),
}
ACTOR_ROLES = {"ANALYST", "SECURITY_ADMIN", "SYSTEM", "ADAPTER"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise LifecycleError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise LifecycleError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _actor(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError("actor is required")
    return value.strip()


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    sequence: int
    from_state: Optional[str]
    to_state: str
    actor: str
    actor_role: str
    timestamp: str
    reason: str
    details: Dict[str, Any]
    previous_event_hash: Optional[str]
    event_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActionLifecycle:
    lifecycle_id: str
    recommendation_id: str
    recommendation_hash: str
    investigation_id: str
    recommended_action: str
    state: str
    reversible: bool
    created_at: str
    updated_at: str
    events: Tuple[AuditEvent, ...]
    executes_external_actions: bool = False

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise LifecycleError(f"unsupported lifecycle state: {self.state}")
        if self.executes_external_actions:
            raise LifecycleError("audit lifecycle cannot execute external actions")

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["events"] = [event.to_dict() for event in self.events]
        return result


def _event(
    sequence: int,
    from_state: Optional[str],
    to_state: str,
    actor: str,
    actor_role: str,
    timestamp: str,
    reason: str,
    details: Optional[Dict[str, Any]],
    previous_event_hash: Optional[str],
) -> AuditEvent:
    if actor_role not in ACTOR_ROLES:
        raise LifecycleError(f"unsupported actor_role: {actor_role}")
    if not isinstance(reason, str) or not reason.strip():
        raise LifecycleError("transition reason is required")
    if not isinstance(details or {}, dict):
        raise LifecycleError("event details must be a mapping")
    payload = {
        "sequence": sequence, "from_state": from_state, "to_state": to_state,
        "actor": _actor(actor), "actor_role": actor_role,
        "timestamp": _timestamp(timestamp), "reason": reason.strip(),
        "details": details or {}, "previous_event_hash": previous_event_hash,
    }
    event_hash = _digest(payload)
    return AuditEvent(
        event_id=f"AUD-{event_hash[:16].upper()}", event_hash=event_hash, **payload
    )


def create_lifecycle(
    recommendation: dict,
    actor: str,
    actor_role: str,
    timestamp: str,
    reason: str = "Recommendation entered the review lifecycle.",
    reversible: bool = True,
) -> ActionLifecycle:
    """Create PENDING audit state linked to an immutable recommendation hash."""
    if not isinstance(recommendation, dict):
        raise LifecycleError("recommendation must be a mapping")
    required = ("recommendation_id", "investigation_id", "recommended_action")
    missing = [key for key in required if not recommendation.get(key)]
    if missing:
        raise LifecycleError(f"recommendation missing required fields: {', '.join(missing)}")
    if recommendation.get("executable") is not False:
        raise LifecycleError("only explicitly non-executable recommendations are accepted")
    recommendation_hash = _digest(recommendation)
    created_at = _timestamp(timestamp)
    first = _event(1, None, "PENDING", actor, actor_role, created_at, reason,
                   {"recommendation_hash": recommendation_hash}, None)
    lifecycle_id = f"LIFE-{_digest([recommendation['recommendation_id'], recommendation_hash])[:16].upper()}"
    return ActionLifecycle(
        lifecycle_id=lifecycle_id,
        recommendation_id=recommendation["recommendation_id"],
        recommendation_hash=recommendation_hash,
        investigation_id=recommendation["investigation_id"],
        recommended_action=recommendation["recommended_action"],
        state="PENDING", reversible=bool(reversible), created_at=created_at,
        updated_at=created_at, events=(first,), executes_external_actions=False,
    )


def transition_lifecycle(
    lifecycle: ActionLifecycle,
    to_state: str,
    actor: str,
    actor_role: str,
    timestamp: str,
    reason: str,
    details: Optional[Dict[str, Any]] = None,
) -> ActionLifecycle:
    """Validate and append a decision record; perform no external action."""
    verify_lifecycle_integrity(lifecycle)
    if to_state not in STATES:
        raise LifecycleError(f"unsupported lifecycle state: {to_state}")
    if to_state not in TRANSITIONS[lifecycle.state]:
        raise LifecycleError(f"illegal transition: {lifecycle.state} -> {to_state}")
    if to_state == "REVERSED" and not lifecycle.reversible:
        raise LifecycleError("recommendation/action is not marked reversible")
    if to_state == "REVERSED" and not (details or {}).get("reversal_reference"):
        raise LifecycleError("reversal requires details.reversal_reference")
    if to_state in {"EXECUTED", "FAILED"} and actor_role != "ADAPTER":
        raise LifecycleError("execution outcome records require ADAPTER actor_role")
    if to_state == "EXECUTED" and not (details or {}).get("external_action_reference"):
        raise LifecycleError("executed outcome requires details.external_action_reference")

    occurred_at = _timestamp(timestamp)
    if occurred_at < lifecycle.updated_at:
        raise LifecycleError("transition timestamp cannot precede the previous event")
    previous_hash = lifecycle.events[-1].event_hash
    new_event = _event(
        len(lifecycle.events) + 1, lifecycle.state, to_state, actor, actor_role,
        occurred_at, reason, details, previous_hash,
    )
    return replace(
        lifecycle, state=to_state, updated_at=occurred_at,
        events=(*lifecycle.events, new_event),
    )


def verify_lifecycle_integrity(
    lifecycle: ActionLifecycle,
    original_recommendation: Optional[dict] = None,
) -> bool:
    """Verify hash chain, ordering, state, and optional original linkage."""
    if not lifecycle.events:
        raise LifecycleError("lifecycle must contain at least one event")
    previous = None
    expected_from = None
    last_timestamp = None
    for index, event in enumerate(lifecycle.events, 1):
        if event.sequence != index:
            raise LifecycleError("audit event sequence is invalid")
        if event.previous_event_hash != previous:
            raise LifecycleError("audit event hash link is invalid")
        if event.from_state != expected_from:
            raise LifecycleError("audit event state chain is invalid")
        payload = {
            "sequence": event.sequence, "from_state": event.from_state,
            "to_state": event.to_state, "actor": event.actor,
            "actor_role": event.actor_role, "timestamp": event.timestamp,
            "reason": event.reason, "details": event.details,
            "previous_event_hash": event.previous_event_hash,
        }
        if _digest(payload) != event.event_hash:
            raise LifecycleError("audit event integrity check failed")
        if f"AUD-{event.event_hash[:16].upper()}" != event.event_id:
            raise LifecycleError("audit event ID does not match its content")
        if last_timestamp and event.timestamp < last_timestamp:
            raise LifecycleError("audit timestamps are not monotonic")
        previous = event.event_hash
        expected_from = event.to_state
        last_timestamp = event.timestamp
    if lifecycle.state != lifecycle.events[-1].to_state:
        raise LifecycleError("lifecycle state does not match final event")
    if original_recommendation is not None:
        if _digest(original_recommendation) != lifecycle.recommendation_hash:
            raise LifecycleError("original recommendation integrity check failed")
        if original_recommendation.get("recommendation_id") != lifecycle.recommendation_id:
            raise LifecycleError("recommendation ID linkage is invalid")
    return True
