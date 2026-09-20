"""Offline BEC-specific advisory assessment.

This module combines bounded content indicators with existing forensic
identity, authentication, URL, and relationship evidence. Keywords alone do
not establish BEC and never trigger execution.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class BECIndicator:
    indicator_id: str
    category: str
    label: str
    evidence_ids: List[str]
    basis: str
    confirmed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BECAssessment:
    status: str
    workflow: str
    indicators: List[Dict[str, Any]]
    evidence_ids: List[str]
    recommended_safeguards: List[str]
    counterfactuals: List[str]
    explanation: str
    limitations: List[str]
    executable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_CONTENT_RULES = (
    ("BEC-CONTENT-PAYMENT", "payment_request", re.compile(
        r"\b(?:wire|bank transfer|payment|pay|remittance|funds?)\b", re.I)),
    ("BEC-CONTENT-BANK-CHANGE", "bank_account_change", re.compile(
        r"\b(?:new|updated|change(?:d)?)\s+(?:bank|account|payment)\b|\bchange\s+(?:our\s+)?bank\s+details\b", re.I)),
    ("BEC-CONTENT-INVOICE", "invoice_request", re.compile(
        r"\b(?:invoice|purchase order|vendor payment)\b", re.I)),
    ("BEC-CONTENT-GIFT-CARD", "gift_card_request", re.compile(
        r"\bgift\s*cards?\b", re.I)),
    ("BEC-CONTENT-PAYROLL", "payroll_redirection", re.compile(
        r"\b(?:payroll|direct deposit|salary)\b", re.I)),
)
_BEHAVIOR_RULES = (
    ("BEC-BEHAVIOR-URGENCY", "urgency_language", re.compile(
        r"\b(?:urgent|immediately|asap|right away|today)\b", re.I)),
    ("BEC-BEHAVIOR-SECRECY", "secrecy_language", re.compile(
        r"\b(?:confidential|do not tell|keep this between us|secret)\b", re.I)),
)
_IDENTITY_SOURCES = {
    "header:reply_to_vs_from", "header:return_path_vs_from",
    "identity:reply_to_domain_mismatch", "identity:display_name_brand_impersonation",
    "identity:display_name_contains_address", "identity:lookalike_domain",
    "identity:homoglyph_lookalike", "identity:punycode_domain",
}
_AUTH_SOURCES = {
    "auth:spf_fail", "auth:dkim_weak", "auth:dmarc_weak",
    "auth:alignment_mismatch", "auth:header_manipulation_suspected",
}
_URL_SOURCES = {"url:structural_analysis"}


def _text(parsed_email: dict) -> str:
    # Analysis is local. Indicator output never copies body text.
    values = [
        parsed_email.get("subject") or "",
        parsed_email.get("body_plain") or "",
        parsed_email.get("body_html_text") or "",
    ]
    return "\n".join(values)[:200_000]


def _source_indicators(evidence_bundle: dict, sources: set, category: str) -> List[BECIndicator]:
    matched = [e for e in (evidence_bundle or {}).get("evidence", []) if e.get("source") in sources]
    if not matched:
        return []
    return [BECIndicator(
        indicator_id=f"BEC-{category}-FORENSIC",
        category=category,
        label=f"{category.lower()}_forensic_indicator",
        evidence_ids=sorted({e.get("evidence_id") for e in matched if e.get("evidence_id")}),
        basis="Existing TRACE-X forensic evidence matched this BEC indicator category.",
    )]


def assess_bec(parsed_email: dict, evidence_bundle: dict, threat_graph: dict) -> dict:
    """Return a deterministic, evidence-traceable, advisory-only BEC assessment."""
    parsed_email = parsed_email or {}
    evidence_bundle = evidence_bundle or {}
    content = _text(parsed_email)
    indicators: List[BECIndicator] = []

    for indicator_id, label, pattern in _CONTENT_RULES:
        if pattern.search(content):
            indicators.append(BECIndicator(
                indicator_id, "CONTENT", label, [],
                "A bounded local pattern matched the subject or message text; raw text is not copied into this assessment.",
            ))
    for indicator_id, label, pattern in _BEHAVIOR_RULES:
        if pattern.search(content):
            indicators.append(BECIndicator(
                indicator_id, "BEHAVIORAL", label, [],
                "A bounded local language pattern matched; this is heuristic and does not prove intent.",
            ))

    indicators += _source_indicators(evidence_bundle, _IDENTITY_SOURCES, "IDENTITY")
    indicators += _source_indicators(evidence_bundle, _AUTH_SOURCES, "AUTHENTICATION")
    indicators += _source_indicators(evidence_bundle, _URL_SOURCES, "URL")

    categories = {item.category for item in indicators}
    content_present = "CONTENT" in categories
    corroborating = categories & {"IDENTITY", "AUTHENTICATION", "URL"}
    behavioral = "BEHAVIORAL" in categories
    threat_class = str((threat_graph or {}).get("threat_class") or "UNKNOWN").upper()

    # Keywords alone never establish a BEC workflow. Require content plus
    # forensic corroboration, or an existing evidence-derived BEC class plus
    # at least one BEC content/behavior signal.
    if content_present and corroborating:
        status = "REVIEW_RECOMMENDED"
    elif threat_class == "BEC" and (content_present or behavioral) and corroborating:
        status = "REVIEW_RECOMMENDED"
    elif content_present or threat_class == "BEC":
        status = "INSUFFICIENT_CORROBORATION"
    else:
        status = "NOT_INDICATED"

    evidence_ids = sorted({eid for item in indicators for eid in item.evidence_ids})
    safeguards = []
    if status == "REVIEW_RECOMMENDED":
        safeguards = [
            "Require an analyst to review the original evidence before relying on the request.",
            "Verify the apparent sender and request through a previously known out-of-band channel.",
        ]
        if any(item.label in {"payment_request", "bank_account_change", "invoice_request", "payroll_redirection", "gift_card_request"} for item in indicators):
            safeguards.append("Require the organization's normal financial approval and change-verification process.")

    counterfactuals = [
        "If the request and apparent sender are independently verified through a known out-of-band channel, the BEC concern may be reduced.",
        "If identity or authentication anomalies are corrected or shown to be expected, the assessment requires reassessment.",
    ]
    if "CONTENT" in categories and not corroborating:
        counterfactuals.append(
            "The content indicator alone is insufficient; corroborating identity, authentication, relationship, or infrastructure evidence could change the assessment."
        )

    explanation = {
        "REVIEW_RECOMMENDED": "BEC-related content is corroborated by forensic identity, authentication, or URL evidence. Human verification is recommended; malicious intent is not established.",
        "INSUFFICIENT_CORROBORATION": "A BEC-related content signal or prior BEC classification exists, but the workflow lacks enough corroboration for a stronger recommendation.",
        "NOT_INDICATED": "The current message does not meet the deterministic BEC workflow criteria.",
    }[status]

    return BECAssessment(
        status=status,
        workflow="OFFLINE_ADVISORY_ONLY",
        indicators=[item.to_dict() for item in indicators],
        evidence_ids=evidence_ids,
        recommended_safeguards=safeguards,
        counterfactuals=counterfactuals,
        explanation=explanation,
        limitations=[
            "Content and behavioral indicators are deterministic heuristics, not proof of intent.",
            "No relationship history, mailbox telemetry, external reputation, or financial system was queried.",
            "No message, payment, hold, quarantine, or external action is performed.",
        ],
        executable=False,
    ).to_dict()
