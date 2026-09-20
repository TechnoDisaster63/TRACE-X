"""M14 - immutable offline analyst feedback records.

Feedback is stored separately from forensic evidence and recommendations. It
produces review/tuning summaries only: no source object mutation, model
training, policy change, action execution, or persistence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Tuple


class FeedbackError(ValueError):
    """Feedback input or integrity is invalid."""


DECISION_TYPES = {
    "ACTION_ACCEPTED", "ACTION_REJECTED", "FALSE_POSITIVE", "FALSE_NEGATIVE",
    "TRUSTED_SENDER", "SUSPICIOUS_SENDER_CONFIRMED", "THREAT_ESCALATED",
    "BENIGN_BUSINESS_EMAIL", "NEEDS_MORE_EVIDENCE",
}
ACTOR_ROLES = {"ANALYST", "SECURITY_ADMIN", "SYSTEM"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _timestamp(value: str) -> str:
    if not isinstance(value, str):
        raise FeedbackError("decided_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FeedbackError("decided_at must be an ISO-8601 string") from exc
    if parsed.tzinfo is None:
        raise FeedbackError("decided_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class FeedbackRecord:
    feedback_id: str
    decision_type: str
    actor: str
    actor_role: str
    decided_at: str
    reason: str
    investigation_id: str
    recommendation_id: str
    evidence_ids: Tuple[str, ...]
    original_evidence_hash: str
    original_recommendation_hash: str
    policy_ids: Tuple[str, ...]
    policy_versions: Tuple[str, ...]
    rule_versions: Tuple[str, ...]
    details: Dict[str, Any]
    record_hash: str
    mutates_originals: bool = False
    executes_actions: bool = False
    trains_model: bool = False

    def __post_init__(self) -> None:
        if self.decision_type not in DECISION_TYPES:
            raise FeedbackError(f"unsupported decision_type: {self.decision_type}")
        if self.actor_role not in ACTOR_ROLES:
            raise FeedbackError(f"unsupported actor_role: {self.actor_role}")
        if self.mutates_originals or self.executes_actions or self.trains_model:
            raise FeedbackError("feedback records cannot mutate, execute, or train")

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        for key in ("evidence_ids", "policy_ids", "policy_versions", "rule_versions"):
            result[key] = list(result[key])
        return result


def create_feedback_record(
    decision_type: str,
    actor: str,
    actor_role: str,
    decided_at: str,
    reason: str,
    investigation: dict,
    recommendation: dict,
    policy_versions: Optional[Iterable[str]] = None,
    rule_versions: Optional[Iterable[str]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> FeedbackRecord:
    """Create one immutable decision record linked to original snapshots."""
    if decision_type not in DECISION_TYPES:
        raise FeedbackError(f"unsupported decision_type: {decision_type}")
    if not isinstance(actor, str) or not actor.strip():
        raise FeedbackError("actor is required")
    if actor_role not in ACTOR_ROLES:
        raise FeedbackError(f"unsupported actor_role: {actor_role}")
    if not isinstance(reason, str) or not reason.strip():
        raise FeedbackError("reason is required")
    if not isinstance(investigation, dict) or not investigation.get("investigation_id"):
        raise FeedbackError("investigation with investigation_id is required")
    if not isinstance(recommendation, dict) or not recommendation.get("recommendation_id"):
        raise FeedbackError("recommendation with recommendation_id is required")
    if recommendation.get("investigation_id") != investigation.get("investigation_id"):
        raise FeedbackError("recommendation and investigation IDs do not match")
    if details is not None and not isinstance(details, dict):
        raise FeedbackError("details must be a mapping")

    evidence = (investigation.get("evidence") or {}).get("evidence", [])
    evidence_ids = tuple(sorted({item.get("evidence_id") for item in evidence if item.get("evidence_id")}))
    rec_evidence_ids = tuple(sorted(set(recommendation.get("evidence_ids") or [])))
    if not set(rec_evidence_ids).issubset(set(evidence_ids)):
        raise FeedbackError("recommendation references evidence outside the investigation")
    policy_ids = tuple(sorted(set(recommendation.get("policy_ids") or [])))
    policy_versions_tuple = tuple(sorted(set(policy_versions or [])))
    rule_versions_tuple = tuple(sorted(set(rule_versions or [])))
    if policy_ids and not policy_versions_tuple:
        raise FeedbackError("policy_versions are required when policy_ids are present")
    if not rule_versions_tuple:
        raise FeedbackError("at least one rule_version is required")

    decided = _timestamp(decided_at)
    evidence_snapshot = {"evidence": evidence, "file_sha256": investigation.get("file_sha256")}
    original_evidence_hash = _digest(evidence_snapshot)
    original_recommendation_hash = _digest(recommendation)
    payload = {
        "decision_type": decision_type, "actor": actor.strip(), "actor_role": actor_role,
        "decided_at": decided, "reason": reason.strip(),
        "investigation_id": investigation["investigation_id"],
        "recommendation_id": recommendation["recommendation_id"],
        "evidence_ids": evidence_ids,
        "original_evidence_hash": original_evidence_hash,
        "original_recommendation_hash": original_recommendation_hash,
        "policy_ids": policy_ids,
        "policy_versions": policy_versions_tuple,
        "rule_versions": rule_versions_tuple,
        "details": details or {},
        "mutates_originals": False, "executes_actions": False, "trains_model": False,
    }
    record_hash = _digest(payload)
    return FeedbackRecord(
        feedback_id=f"FDBK-{record_hash[:16].upper()}", record_hash=record_hash, **payload
    )


def verify_feedback_integrity(
    record: FeedbackRecord,
    investigation: dict,
    recommendation: dict,
) -> bool:
    evidence = (investigation.get("evidence") or {}).get("evidence", [])
    expected_evidence_hash = _digest({
        "evidence": evidence, "file_sha256": investigation.get("file_sha256")
    })
    if expected_evidence_hash != record.original_evidence_hash:
        raise FeedbackError("original evidence integrity check failed")
    if _digest(recommendation) != record.original_recommendation_hash:
        raise FeedbackError("original recommendation integrity check failed")
    if investigation.get("investigation_id") != record.investigation_id:
        raise FeedbackError("investigation linkage is invalid")
    if recommendation.get("recommendation_id") != record.recommendation_id:
        raise FeedbackError("recommendation linkage is invalid")
    payload = record.to_dict()
    payload.pop("feedback_id")
    payload.pop("record_hash")
    for key in ("evidence_ids", "policy_ids", "policy_versions", "rule_versions"):
        payload[key] = tuple(payload[key])
    if _digest(payload) != record.record_hash:
        raise FeedbackError("feedback record integrity check failed")
    if f"FDBK-{record.record_hash[:16].upper()}" != record.feedback_id:
        raise FeedbackError("feedback ID does not match record content")
    return True


def summarize_feedback(records: Iterable[FeedbackRecord]) -> dict:
    """Return deterministic review/tuning counts; make no automatic changes."""
    records = list(records)
    by_decision = {decision: 0 for decision in sorted(DECISION_TYPES)}
    by_rule_version: Dict[str, int] = {}
    by_policy_version: Dict[str, int] = {}
    for record in records:
        if not isinstance(record, FeedbackRecord):
            raise FeedbackError("summary accepts FeedbackRecord values only")
        by_decision[record.decision_type] += 1
        for version in record.rule_versions:
            by_rule_version[version] = by_rule_version.get(version, 0) + 1
        for version in record.policy_versions:
            by_policy_version[version] = by_policy_version.get(version, 0) + 1
    review_flags = []
    if by_decision["FALSE_POSITIVE"]:
        review_flags.append("Review rules/policies associated with false-positive feedback.")
    if by_decision["FALSE_NEGATIVE"]:
        review_flags.append("Review missing evidence and rules associated with false-negative feedback.")
    if by_decision["NEEDS_MORE_EVIDENCE"]:
        review_flags.append("Review evidence-collection gaps; no automatic threshold change is made.")
    return {
        "record_count": len(records),
        "by_decision_type": by_decision,
        "by_rule_version": dict(sorted(by_rule_version.items())),
        "by_policy_version": dict(sorted(by_policy_version.items())),
        "review_flags": review_flags,
        "usage": "REVIEW_AND_TUNING_SUMMARY_ONLY",
        "automatic_rule_changes": False,
        "automatic_policy_changes": False,
        "model_training_performed": False,
        "external_actions": False,
    }
