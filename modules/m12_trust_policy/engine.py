"""M12 - deterministic, advisory-safe trust and policy engine.

Policies select recommendations. They never execute an action. Policy output
can strengthen a base recommendation but cannot silently weaken it; an allow
policy that conflicts with suspicious evidence requires review instead.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


class PolicyValidationError(ValueError):
    """A policy is malformed or contains an unsupported value."""


ACTIONS = {
    "ALLOW_WITH_NOTICE",
    "FLAG_FOR_REVIEW",
    "REQUIRE_ANALYST_REVIEW",
    "HOLD_FOR_REVIEW",
    "ESCALATE_TO_SOC",
    "REQUEST_ADDITIONAL_ANALYSIS",
}
ACTION_RANK = {
    "ALLOW_WITH_NOTICE": 0,
    "REQUEST_ADDITIONAL_ANALYSIS": 1,
    "FLAG_FOR_REVIEW": 2,
    "REQUIRE_ANALYST_REVIEW": 3,
    "HOLD_FOR_REVIEW": 4,
    "ESCALATE_TO_SOC": 5,
}
VALID_MODES = {"ADVISORY", "APPROVAL_REQUIRED"}
VALID_EFFECTS = {"RECOMMEND"}


@dataclass(frozen=True)
class TrustPolicy:
    policy_id: str
    name: str
    version: int
    enabled: bool
    conditions: List[str]
    action: str
    priority: int
    requires_approval: bool
    effect: str = "RECOMMEND"
    created_by: str = "unspecified"
    expires_at: Optional[str] = None
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise PolicyValidationError("policy_id is required and must be a string")
        if not isinstance(self.name, str) or not self.name.strip():
            raise PolicyValidationError("policy name is required and must be a string")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise PolicyValidationError("policy version must be an integer >= 1")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int) or not 0 <= self.priority <= 1000:
            raise PolicyValidationError("policy priority must be an integer between 0 and 1000")
        if not isinstance(self.enabled, bool):
            raise PolicyValidationError("policy enabled must be a boolean")
        if not isinstance(self.requires_approval, bool):
            raise PolicyValidationError("policy requires_approval must be a boolean")
        if not isinstance(self.conditions, list) or not self.conditions or any(not isinstance(c, str) or not c.strip() for c in self.conditions):
            raise PolicyValidationError("policy must contain non-empty conditions")
        if len(set(self.conditions)) != len(self.conditions):
            raise PolicyValidationError("policy conditions must be unique")
        if not isinstance(self.created_by, str) or not self.created_by.strip():
            raise PolicyValidationError("policy created_by must be a non-empty string")
        if not isinstance(self.description, str):
            raise PolicyValidationError("policy description must be a string")
        if not isinstance(self.metadata, dict):
            raise PolicyValidationError("policy metadata must be a mapping")
        if self.action not in ACTIONS:
            raise PolicyValidationError(f"unsupported policy action: {self.action}")
        if self.effect not in VALID_EFFECTS:
            raise PolicyValidationError(f"unsupported policy effect: {self.effect}")
        if ACTION_RANK[self.action] >= ACTION_RANK["REQUIRE_ANALYST_REVIEW"] and not self.requires_approval:
            raise PolicyValidationError("review, hold, and escalation policies require approval")
        if self.expires_at is not None:
            _parse_timestamp(self.expires_at)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise PolicyValidationError("expires_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyValidationError("expires_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_policy(raw: Any) -> TrustPolicy:
    """Validate and normalize a TrustPolicy or policy dictionary."""
    if isinstance(raw, TrustPolicy):
        return raw
    if not isinstance(raw, dict):
        raise PolicyValidationError("policy must be a mapping or TrustPolicy")
    allowed = {field.name for field in TrustPolicy.__dataclass_fields__.values()}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyValidationError(f"unknown policy fields: {', '.join(unknown)}")
    try:
        return TrustPolicy(**raw)
    except TypeError as exc:
        raise PolicyValidationError(f"invalid policy fields: {exc}") from exc


def _now_utc(now: Optional[datetime]) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise PolicyValidationError("evaluation time must include a timezone")
    return value.astimezone(timezone.utc)


def _context_signals(risk: dict, threat_graph: dict, evidence_bundle: dict) -> set:
    signals = {
        f"risk:{str((risk or {}).get('risk_level', 'UNKNOWN')).upper()}",
        f"threat:{str((threat_graph or {}).get('threat_class', 'UNKNOWN')).upper()}",
    }
    for item in (evidence_bundle or {}).get("evidence", []):
        source = item.get("source")
        category = item.get("category")
        module = item.get("module")
        severity = item.get("severity")
        if source:
            signals.add(f"source:{source}")
        if category:
            signals.add(f"category:{str(category).upper()}")
        if module:
            signals.add(f"module:{module}")
        if severity:
            signals.add(f"severity:{str(severity).upper()}")
    return signals


def evaluate_policies(
    policies: Iterable[Any],
    risk: dict,
    threat_graph: dict,
    evidence_bundle: dict,
    base_action: str,
    now: Optional[datetime] = None,
    base_requires_approval: Optional[bool] = None,
) -> dict:
    """Evaluate policies with deterministic precedence and safe conflict rules.

    All conditions use exact string membership in a documented context signal
    set. All conditions in one policy must match. Higher priority wins; policy
    ID is the stable tie-breaker. A tie between different actions resolves to
    the stronger review recommendation. Policy output never executes anything.
    """
    if base_action not in ACTIONS:
        raise PolicyValidationError(f"unsupported base action: {base_action}")
    evaluation_time = _now_utc(now)
    signals = _context_signals(risk, threat_graph, evidence_bundle)
    validated = [validate_policy(p) for p in policies]
    ids = [p.policy_id for p in validated]
    if len(ids) != len(set(ids)):
        raise PolicyValidationError("policy_id values must be unique")

    records = []
    matches = []
    for policy in sorted(validated, key=lambda p: (-p.priority, p.policy_id)):
        expired = bool(policy.expires_at and _parse_timestamp(policy.expires_at) <= evaluation_time)
        missing = sorted(set(policy.conditions) - signals)
        matched = policy.enabled and not expired and not missing
        record = {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "priority": policy.priority,
            "enabled": policy.enabled,
            "expired": expired,
            "matched": matched,
            "matched_conditions": sorted(set(policy.conditions) & signals),
            "missing_conditions": missing,
            "action": policy.action,
            "reason": (
                "Policy matched all conditions."
                if matched else
                "Policy is disabled." if not policy.enabled else
                "Policy is expired." if expired else
                "Policy conditions were not fully satisfied."
            ),
        }
        records.append(record)
        if matched:
            matches.append(policy)

    selected_policy_ids: List[str] = []
    conflict = None
    selected_policy_action = None
    selected_requires_approval = False
    if matches:
        top_priority = matches[0].priority
        top = [p for p in matches if p.priority == top_priority]
        selected_policy_action = max((p.action for p in top), key=lambda action: (ACTION_RANK[action], action))
        selected = [p for p in top if p.action == selected_policy_action]
        selected_policy_ids = sorted(p.policy_id for p in selected)
        selected_requires_approval = any(p.requires_approval for p in selected)
        distinct_actions = sorted({p.action for p in top})
        if len(distinct_actions) > 1:
            conflict = {
                "type": "EQUAL_PRIORITY_ACTION_CONFLICT",
                "policy_ids": sorted(p.policy_id for p in top),
                "actions": distinct_actions,
                "resolution": "STRONGER_REVIEW_ACTION_WINS; NO ACTION EXECUTED",
            }

    effective_action = base_action
    if selected_policy_action and ACTION_RANK[selected_policy_action] > ACTION_RANK[base_action]:
        effective_action = selected_policy_action
    elif selected_policy_action == "ALLOW_WITH_NOTICE" and ACTION_RANK[base_action] > 0:
        conflict = conflict or {
            "type": "ALLOW_VERSUS_FORENSIC_RISK",
            "policy_ids": selected_policy_ids,
            "actions": [selected_policy_action, base_action],
            "resolution": "BASE FORENSIC RECOMMENDATION PRESERVED; HUMAN REVIEW REQUIRED",
        }

    if base_requires_approval is None:
        base_requires_approval = ACTION_RANK[base_action] >= ACTION_RANK["REQUIRE_ANALYST_REVIEW"]
    elif not isinstance(base_requires_approval, bool):
        raise PolicyValidationError("base_requires_approval must be a boolean")
    approval = (
        base_requires_approval
        or selected_requires_approval
        or ACTION_RANK[effective_action] >= ACTION_RANK["REQUIRE_ANALYST_REVIEW"]
    )
    return {
        "evaluation_mode": "ADVISORY_ONLY",
        "default_behavior": "BASE_RECOMMENDATION",
        "evaluated_at": evaluation_time.isoformat(),
        "context_signals": sorted(signals),
        "evaluations": records,
        "matched_policy_ids": [p.policy_id for p in matches],
        "selected_policy_ids": selected_policy_ids,
        "selected_policy_action": selected_policy_action,
        "base_action": base_action,
        "effective_action": effective_action,
        "action_mode": "APPROVAL_REQUIRED" if approval else "ADVISORY",
        "requires_human_approval": approval,
        "conflict": conflict,
        "explanation": (
            "Policies use exact all-condition matching and deterministic priority. "
            "They may strengthen but never silently weaken the forensic recommendation. "
            "No policy action is executed."
        ),
        "executable": False,
    }
