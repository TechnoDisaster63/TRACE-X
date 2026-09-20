"""M11 - advisory-only prevention recommendation engine.

M11 converts completed forensic outputs into an explainable recommendation.
It cannot execute, quarantine, delete, block, or contact another system. Risk
score is one input, never proof of malicious intent and never sufficient for
automation.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from modules.m12_trust_policy.engine import evaluate_policies
from modules.m11_prevention_recommendation.bec import assess_bec

VALID_ACTIONS = {
    "ALLOW_WITH_NOTICE",
    "FLAG_FOR_REVIEW",
    "REQUIRE_ANALYST_REVIEW",
    "HOLD_FOR_REVIEW",
    "ESCALATE_TO_SOC",
    "REQUEST_ADDITIONAL_ANALYSIS",
}
VALID_MODES = {"ADVISORY", "APPROVAL_REQUIRED"}
VALID_STATUSES = {"PENDING"}


@dataclass(frozen=True)
class PreventionRecommendation:
    recommendation_id: str
    investigation_id: str
    risk_level: str
    threat_class: str
    recommended_action: str
    action_mode: str
    confidence: str
    evidence_ids: List[str]
    triggered_rules: List[str]
    reason: str
    potential_impact: str
    reversibility: str
    policy_ids: List[str]
    requires_human_approval: bool
    created_at: str
    status: str = "PENDING"
    explanation: List[Dict[str, Any]] = field(default_factory=list)
    counterfactuals: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    executable: bool = False

    def __post_init__(self) -> None:
        if self.recommended_action not in VALID_ACTIONS:
            raise ValueError(f"Unsupported prevention action: {self.recommended_action}")
        if self.action_mode not in VALID_MODES:
            raise ValueError(f"Unsafe or unsupported action mode: {self.action_mode}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Unsupported initial recommendation status: {self.status}")
        if self.executable:
            raise ValueError("M11 recommendations are advisory-only and cannot execute")
        if self.action_mode == "APPROVAL_REQUIRED" and not self.requires_human_approval:
            raise ValueError("Approval-required recommendations require human approval")
        if self.action_mode == "ADVISORY" and self.requires_human_approval:
            raise ValueError("Advisory recommendations cannot require human approval")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _stable_id(investigation_id: str, action: str, evidence_ids: List[str]) -> str:
    material = "|".join([investigation_id, action, *sorted(evidence_ids)])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12].upper()
    return f"REC-{digest}"


def _select_action(risk_level: str, threat_class: str, evidence_ids: List[str]) -> Dict[str, Any]:
    if not evidence_ids:
        return {
            "action": "REQUEST_ADDITIONAL_ANALYSIS",
            "mode": "ADVISORY",
            "approval": False,
            "rules": ["M11-INSUFFICIENT-CONTEXT"],
            "reason": "No traceable risk-contributing evidence is available, so TRACE-X cannot support a stronger recommendation.",
            "impact": "Additional evidence may permit a more specific assessment; no message control is performed.",
            "reversibility": "No external state changes are made.",
        }
    if risk_level == "LOW":
        return {
            "action": "ALLOW_WITH_NOTICE",
            "mode": "ADVISORY",
            "approval": False,
            "rules": ["M11-LOW-ADVISORY"],
            "reason": "The current rule-based assessment is LOW risk; normal caution remains appropriate.",
            "impact": "The message remains available. TRACE-X does not assert that LOW risk means safe.",
            "reversibility": "Advisory only; no state change to reverse.",
        }
    if risk_level == "MEDIUM":
        action = "REQUIRE_ANALYST_REVIEW" if threat_class in {"BEC", "PHISHING", "SPOOFING"} else "FLAG_FOR_REVIEW"
        return {
            "action": action,
            "mode": "APPROVAL_REQUIRED",
            "approval": True,
            "rules": ["M11-MEDIUM-HUMAN-REVIEW"],
            "reason": "The evidence indicates anomalies, but it is insufficient for an automatic block or quarantine.",
            "impact": "An analyst should review the message before relying on it; TRACE-X performs no hold or quarantine.",
            "reversibility": "The recommendation may be rejected or superseded after review; no action has executed.",
        }
    if risk_level in {"HIGH", "CRITICAL"}:
        rules = ["M11-HIGH-HUMAN-HOLD"]
        if threat_class in {"BEC", "PHISHING"}:
            rules.append("M11-IDENTITY-THREAT-ESCALATION")
        return {
            "action": "HOLD_FOR_REVIEW",
            "mode": "APPROVAL_REQUIRED",
            "approval": True,
            "rules": rules,
            "reason": "Multiple or high-severity indicators support urgent human review, but risk score alone does not prove malicious intent.",
            "impact": "A security workflow may choose to hold the message after approval; this offline prototype performs no hold, quarantine, or block.",
            "reversibility": "The pending recommendation can be rejected; any future adapter must define reversal before execution.",
        }
    return {
        "action": "REQUEST_ADDITIONAL_ANALYSIS",
        "mode": "ADVISORY",
        "approval": False,
        "rules": ["M11-UNKNOWN-RISK"],
        "reason": "The risk level is missing or unsupported, so no stronger recommendation is justified.",
        "impact": "No action is performed.",
        "reversibility": "No external state changes are made.",
    }


def _explanations(risk_factors: List[dict]) -> List[dict]:
    explanations = []
    for factor in risk_factors:
        explanations.append({
            "evidence_id": factor.get("evidence_id"),
            "module": factor.get("module"),
            "source": factor.get("source"),
            "severity": factor.get("severity"),
            "finding": factor.get("finding"),
            "why_it_matters": (
                "This observation contributed to the deterministic risk assessment. "
                "It is evidence for review, not proof of malicious intent."
            ),
            "automation_eligible": bool(factor.get("automated_prevention_eligible", True)),
        })
    return explanations


def _counterfactuals(risk: dict, threat_class: str) -> List[str]:
    items = [
        "If relevant evidence is corrected, removed, or independently disproved, the recommendation requires reassessment.",
        "If additional corroborating evidence is found, a stronger human-reviewed recommendation may be appropriate.",
    ]
    constraints = risk.get("prevention_constraints", {})
    if constraints.get("untrusted_reported_authentication_evidence_ids"):
        items.append(
            "If authentication results are obtained from an explicitly trusted receiving boundary or independently verified, authentication-related concern may require reassessment."
        )
    if threat_class == "BEC":
        items.append(
            "If the apparent sender and request are independently verified through a known out-of-band channel, the BEC recommendation may be reduced."
        )
    if threat_class == "PHISHING":
        items.append(
            "If suspicious identities, domains, and URLs are confirmed as approved organizational resources, the phishing recommendation may be reduced."
        )
    return items


def generate_prevention_recommendation(
    investigation_id: str,
    evidence_bundle: dict,
    risk: dict,
    threat_graph: dict,
    policies: Optional[List[dict]] = None,
    parsed_email: Optional[dict] = None,
) -> dict:
    """Return one typed, explainable, non-executable prevention recommendation."""
    evidence_bundle = evidence_bundle or {}
    risk = risk or {}
    threat_graph = threat_graph or {}
    risk_factors = list(risk.get("risk_factors") or [])
    evidence_ids = [f.get("evidence_id") for f in risk_factors if f.get("evidence_id")]
    risk_level = str(risk.get("risk_level") or "UNKNOWN").upper()
    confidence = str(risk.get("confidence") or "LOW").upper()
    threat_class = str(threat_graph.get("threat_class") or "UNKNOWN").upper()
    selected = _select_action(risk_level, threat_class, evidence_ids)

    constraints = risk.get("prevention_constraints", {})
    untrusted_auth = constraints.get("untrusted_reported_authentication_evidence_ids", [])
    limitations = [
        "M11 is advisory-only and has no execution adapter.",
        "Risk and confidence are rule-based labels, not calibrated probabilities.",
        "A recommendation does not establish malicious intent.",
        "No external reputation, mailbox, SIEM, or secure email gateway check was performed.",
    ]
    if untrusted_auth:
        limitations.append(
            "Reported authentication evidence from an untrusted source may support analyst review but cannot support automated prevention action."
        )

    bec_assessment = assess_bec(parsed_email or {}, evidence_bundle, threat_graph)
    policy_decision = evaluate_policies(
        policies or [], risk, threat_graph, evidence_bundle, selected["action"],
        base_requires_approval=selected["approval"],
    )
    effective_action = policy_decision["effective_action"]
    if effective_action != selected["action"]:
        selected = dict(selected)
        selected["action"] = effective_action
        selected["mode"] = policy_decision["action_mode"]
        selected["approval"] = policy_decision["requires_human_approval"]
        selected["rules"] = [*selected["rules"], "M12-POLICY-DECISION"]
        selected["reason"] = selected["reason"] + " " + policy_decision["explanation"]

    recommendation = PreventionRecommendation(
        recommendation_id=_stable_id(investigation_id or "UNKNOWN", selected["action"], evidence_ids),
        investigation_id=investigation_id or "UNKNOWN",
        risk_level=risk_level,
        threat_class=threat_class,
        recommended_action=selected["action"],
        action_mode=selected["mode"],
        confidence=confidence,
        evidence_ids=evidence_ids,
        triggered_rules=selected["rules"],
        reason=selected["reason"],
        potential_impact=selected["impact"],
        reversibility=selected["reversibility"],
        policy_ids=policy_decision["selected_policy_ids"],
        requires_human_approval=selected["approval"],
        created_at=datetime.now(timezone.utc).isoformat(),
        explanation=_explanations(risk_factors),
        counterfactuals=list(dict.fromkeys([
            *_counterfactuals(risk, threat_class),
            *bec_assessment["counterfactuals"],
        ])),
        limitations=limitations,
        executable=False,
    )
    result = recommendation.to_dict()
    result["policy_decision"] = policy_decision
    result["bec_assessment"] = bec_assessment
    return result
