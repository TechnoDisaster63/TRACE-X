"""
M10 — Report Generator

Assembles the final TRACE-X report from the REAL outputs of M01 (ParsedEmail
dict), M07 (EvidenceBundle dict), M08 (RiskAssessment-shaped dict), and M09
(ThreatGraph dict). All upstream data is treated as untrusted; every section
degrades gracefully on missing/malformed input rather than raising.

Output: a dict (primary), plus to_json() / to_text() helpers.
Recommendations are rule-based and evidence-driven, not hardcoded strings.
"""
from __future__ import annotations

import json
import textwrap
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

REPORT_VERSION = "1.0"
PIPELINE_VERSION = "TRACE-X-M10"


@dataclass(frozen=True)
class _RecommendationRule:
    rule_id: str
    trigger_levels: frozenset
    trigger_classes: frozenset  # empty = all classes
    priority: int  # 1 = most urgent
    action: str
    rationale: str


_RECOMMENDATION_RULES: List[_RecommendationRule] = [
    _RecommendationRule(
        "DO_NOT_CLICK", frozenset({"HIGH", "CRITICAL"}), frozenset(), 1,
        "Do not click any links or open any attachments in this message.",
        "High-risk messages have a significant probability of containing malicious URLs or payloads.",
    ),
    _RecommendationRule(
        "DO_NOT_REPLY", frozenset({"HIGH", "CRITICAL"}), frozenset({"BEC", "PHISHING"}), 1,
        "Do not reply to this message. Verify the sender's identity through a known, trusted channel first.",
        "Reply-To redirection and identity deception are primary vectors in BEC and phishing attacks.",
    ),
    _RecommendationRule(
        "ESCALATE_SECURITY", frozenset({"CRITICAL"}), frozenset(), 1,
        "Escalate to the security team immediately and preserve the original message headers for forensic analysis.",
        "CRITICAL risk indicates multiple corroborating threat signals.",
    ),
    _RecommendationRule(
        "MANUAL_REVIEW", frozenset({"MEDIUM", "HIGH"}), frozenset(), 2,
        "Route this message for manual security review before any action is taken.",
        "MEDIUM/HIGH risk indicates anomalies that may not be definitively malicious but warrant human judgement.",
    ),
    _RecommendationRule(
        "VERIFY_SENDER_BEC", frozenset({"MEDIUM", "HIGH", "CRITICAL"}), frozenset({"BEC"}), 2,
        "Contact the apparent sender via phone or a separate, previously-known channel to confirm they sent this message.",
        "BEC attacks impersonate trusted individuals; out-of-band verification is the most reliable countermeasure.",
    ),
    _RecommendationRule(
        "CHECK_AUTH_CONFIG", frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"}), frozenset({"SPOOFING"}), 3,
        "Review SPF, DKIM, and DMARC configuration for the sender domain.",
        "Authentication failures combined with identity signals suggest the sending infrastructure is not authorised.",
    ),
    _RecommendationRule(
        "QUARANTINE", frozenset({"HIGH", "CRITICAL"}), frozenset(), 2,
        "Consider quarantining this message to prevent further interaction by the recipient.",
        "Quarantine limits exposure while the message undergoes review.",
    ),
    _RecommendationRule(
        "LOW_RISK_STANDARD", frozenset({"LOW"}), frozenset(), 4,
        "No immediate action required. Apply standard email-hygiene practices.",
        "Evidence does not indicate a significant threat at this time.",
    ),
    _RecommendationRule(
        "LOW_CONFIDENCE_CAVEAT", frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"}), frozenset(), 3,
        "Treat these findings as indicative, not conclusive - assessment confidence is LOW due to limited evidence.",
        "Low confidence means the assessment may be incomplete; additional analysis may change the classification.",
    ),
]


def _build_recommendations(risk_level: str, confidence: str, threat_class: str) -> List[dict]:
    applicable: List[dict] = []
    seen = set()
    for rule in _RECOMMENDATION_RULES:
        if risk_level not in rule.trigger_levels:
            continue
        if rule.trigger_classes and threat_class not in rule.trigger_classes:
            continue
        if rule.rule_id == "LOW_CONFIDENCE_CAVEAT" and confidence != "LOW":
            continue
        if rule.rule_id in seen:
            continue
        seen.add(rule.rule_id)
        applicable.append({
            "rule_id": rule.rule_id,
            "priority": rule.priority,
            "action": rule.action,
            "rationale": rule.rationale,
        })
    applicable.sort(key=lambda r: r["priority"])
    return applicable


def generate_report(
    parsed_email: dict,
    evidence_bundle: dict,
    risk: dict,
    threat_graph: dict,
    investigation_id: str = None,
    file_name: str = None,
    identity_result: dict = None,
    received_result: dict = None,
    auth_result: dict = None,
    campaign: dict = None,
) -> dict:
    """Build the full TRACE-X report dict from real pipeline outputs.
    Never raises - missing/malformed sections degrade gracefully.

    investigation_id / file_name / identity_result / received_result /
    auth_result / campaign are optional so existing callers (and existing
    tests) that only pass the original 4 positional arguments keep working
    unchanged; when supplied, they populate the additional report sections
    (Investigation ID, File, Identity Analysis, Received Chain, Campaign
    Relationships)."""
    parsed_email = parsed_email or {}
    evidence_bundle = evidence_bundle or {"evidence": [], "evidence_count": 0}
    risk = risk or {"score": 0, "risk_level": "LOW", "risk_factors": [], "confidence": "LOW"}
    threat_graph = threat_graph or {"threat_class": "UNKNOWN", "threat_class_confidence": "LOW"}

    report_id = str(uuid.uuid4())
    generated_at = datetime.now(timezone.utc).isoformat()

    email_id = parsed_email.get("from_") or "unknown-email"
    risk_score = risk.get("score", 0)
    risk_level = risk.get("risk_level", "LOW")
    confidence = risk.get("confidence", "LOW")
    threat_class = threat_graph.get("threat_class", "UNKNOWN")
    threat_class_confidence = threat_graph.get("threat_class_confidence", "LOW")

    header = {
        "report_id": report_id,
        "investigation_id": investigation_id,
        "generated_at": generated_at,
        "pipeline": PIPELINE_VERSION,
        "version": REPORT_VERSION,
        "email_id": email_id,
        "file_name": file_name,
        "subject": parsed_email.get("subject"),
        "file_sha256": parsed_email.get("file_sha256"),
        "verdict": {"risk_level": risk_level, "risk_score": risk_score, "threat_class": threat_class},
    }

    verdict_parts = [
        f"Risk level is {risk_level} (score: {risk_score}/100, confidence: {confidence}). "
        f"Threat classification: {threat_class} (confidence: {threat_class_confidence})."
    ]
    if risk.get("explanation"):
        verdict_parts.append(risk["explanation"])
    reasons = threat_graph.get("threat_class_reasons") or []
    if reasons:
        verdict_parts.append(reasons[0])
    executive = {
        "verdict": " ".join(verdict_parts),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "threat_class": threat_class,
    }

    risk_summary = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "risk_factors": risk.get("risk_factors", []),
        "score_breakdown": risk.get("score_breakdown", {}),
        "scoring_method": risk.get("scoring_method", ""),
    }

    threat_analysis = {
        "threat_class": threat_class,
        "threat_class_confidence": threat_class_confidence,
        "threat_class_reasons": reasons,
        "patterns_detected": threat_graph.get("threat_patterns", []),
        "pattern_count": len(threat_graph.get("threat_patterns", [])),
        "graph_summary": threat_graph.get("summary", ""),
    }

    evidence_items = evidence_bundle.get("evidence", [])
    by_severity: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    for e in evidence_items:
        sev = e.get("severity", "UNKNOWN")
        src = e.get("source", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_source[src] = by_source.get(src, 0) + 1
    evidence_log = {
        "total_items": len(evidence_items),
        "by_severity": by_severity,
        "by_source": by_source,
        "items": evidence_items,
    }

    authentication = {
        "raw_authentication_results": parsed_email.get("authentication_results", []),
        "spf": (auth_result or {}).get("spf", {}),
        "dkim": (auth_result or {}).get("dkim", {}),
        "dmarc": (auth_result or {}).get("dmarc", {}),
        "alignment": (auth_result or {}).get("alignment", {}),
        "findings": (auth_result or {}).get("findings", []),
    }

    identity_analysis = {
        "display_name": (identity_result or {}).get("display_name"),
        "from_address": (identity_result or {}).get("from_address"),
        "from_domain": (identity_result or {}).get("from_domain"),
        "reply_to_domain": (identity_result or {}).get("reply_to_domain"),
        "return_path_domain": (identity_result or {}).get("return_path_domain"),
        "findings": (identity_result or {}).get("findings", []),
    }

    received_chain = {
        "hop_count": (received_result or {}).get("hop_count", 0),
        "chain": (received_result or {}).get("chain", []),
        "findings": (received_result or {}).get("findings", []),
    }

    indicators = {
        "node_count": threat_graph.get("node_count", 0),
        "edge_count": threat_graph.get("edge_count", 0),
        "nodes": threat_graph.get("nodes", []),
        "edges": threat_graph.get("edges", []),
    }

    campaign_relationships = campaign or {
        "campaign_id": None,
        "is_part_of_campaign": False,
        "related_email_count": 0,
        "note": "This investigation was analyzed individually; no multi-email "
                "campaign correlation was requested or performed.",
    }

    limitations = [
        "This is a prototype rule-based analysis engine, not a production security product.",
        "No DNS lookups are performed anywhere in this pipeline; SPF/DKIM/DMARC and domain-"
        "alignment results reflect the Authentication-Results header as received, not live "
        "re-verification against the sending domain's actual DNS records.",
        "URLs are analyzed structurally only and are never visited or fetched.",
        "Brand-impersonation and look-alike-domain detection use a small, illustrative, "
        "hardcoded reference set - not a comprehensive brand-protection database.",
        "Risk scoring is a transparent, additive rule-based model, not a trained ML classifier.",
        "Campaign correlation (when performed) is based on shared observable indicators across "
        "the emails supplied in a single batch; it does not query any external threat-"
        "intelligence source.",
        "Findings in this report describe observed evidence and its likely interpretation - "
        "they do not constitute legal, regulatory, or courtroom proof of attribution.",
    ]

    analyst_notes = [
        "Review all HIGH/CRITICAL findings against the Evidence Log before taking action; "
        "every finding is traceable to a specific evidence_id.",
        "Authentication results are one signal among several - an authentication PASS does "
        "not, by itself, establish that a message is safe, and an authentication FAIL does "
        "not, by itself, establish malicious intent.",
    ]
    if confidence == "LOW":
        analyst_notes.append(
            "Overall confidence is LOW: treat this assessment as indicative rather than "
            "conclusive, and consider requesting additional evidence or a manual review."
        )
    if campaign and campaign.get("is_part_of_campaign"):
        analyst_notes.append(
            f"This message shares observable indicators with {campaign.get('related_email_count', 0)} "
            "other message(s) in the analyzed batch - see Campaign Relationships."
        )

    recommendations = _build_recommendations(risk_level, confidence, threat_class)

    metadata = {
        "pipeline_version": PIPELINE_VERSION,
        "report_version": REPORT_VERSION,
        "generated_at": generated_at,
        "graph_id": threat_graph.get("graph_id"),
        "graph_built_at": threat_graph.get("built_at"),
    }

    return {
        "report_id": report_id,
        "investigation_id": investigation_id,
        "report_version": REPORT_VERSION,
        "generated_at": generated_at,
        "email_id": email_id,
        "file_name": file_name,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_confidence": confidence,
        "threat_class": threat_class,
        "threat_class_confidence": threat_class_confidence,
        "header": header,
        "executive": executive,
        "risk_summary": risk_summary,
        "threat_analysis": threat_analysis,
        "evidence_log": evidence_log,
        "authentication": authentication,
        "identity_analysis": identity_analysis,
        "received_chain": received_chain,
        "indicators": indicators,
        "campaign_relationships": campaign_relationships,
        "recommendations": recommendations,
        "limitations": limitations,
        "analyst_notes": analyst_notes,
        "metadata": metadata,
    }


def to_json(report: dict, indent: int = 2) -> str:
    try:
        return json.dumps(report, indent=indent, default=str)
    except Exception:
        return json.dumps({"error": "serialization_failed"})


def to_text(report: dict) -> str:
    """Human-readable plain-text rendering. Never raises."""
    sep = "=" * 60
    thin = "-" * 60
    lines: List[str] = []

    lines += [sep, "TRACE-X ANALYSIS REPORT", sep]
    lines.append(f"Report ID       : {report.get('report_id')}")
    lines.append(f"Investigation ID: {report.get('investigation_id')}")
    lines.append(f"File            : {report.get('file_name')}")
    lines.append(f"Generated       : {report.get('generated_at')}")
    lines.append(f"Email ID        : {report.get('email_id')}")
    lines.append("")

    lines += [thin, "EXECUTIVE SUMMARY", thin]
    lines.append(report.get("executive", {}).get("verdict", ""))
    lines.append("")

    lines += [thin, "RISK ASSESSMENT", thin]
    rs = report.get("risk_summary", {})
    lines.append(f"Risk Level : {rs.get('risk_level')}")
    lines.append(f"Risk Score : {rs.get('risk_score')} / 100")
    lines.append(f"Confidence : {rs.get('confidence')}")
    lines.append("Risk Factors:")
    for f in rs.get("risk_factors", []):
        lines.append(
            f"  [{f.get('effective_weight', f.get('weight', 0)):>3} pts] "
            f"{f.get('finding', '?')} ({f.get('severity', '?')}) - {f.get('module', '?')}"
        )
    lines.append("")

    lines += [thin, "THREAT ANALYSIS", thin]
    ta = report.get("threat_analysis", {})
    lines.append(f"Threat Class : {ta.get('threat_class')}")
    lines.append(f"Confidence   : {ta.get('threat_class_confidence')}")
    patterns = ta.get("patterns_detected", [])
    if patterns:
        lines.append("Patterns Detected:")
        for p in patterns:
            lines.append(f"  * {p.get('name', '?')} [{p.get('severity', '?')}]")
            lines.append("    " + textwrap.fill(p.get("description", ""), width=56, subsequent_indent="    "))
    else:
        lines.append("  No threat patterns matched.")
    lines.append("")

    lines += [thin, "RECOMMENDATIONS", thin]
    for i, rec in enumerate(report.get("recommendations", []), 1):
        lines.append(f"{i}. [P{rec.get('priority', '?')}] {rec.get('action', '')}")
    lines.append("")

    lines += [thin, "EVIDENCE LOG", thin]
    ev = report.get("evidence_log", {})
    lines.append(f"Total items : {ev.get('total_items', 0)}")
    lines.append(f"By severity : {ev.get('by_severity', {})}")
    lines.append("")

    lines += [thin, "INDICATORS (THREAT GRAPH)", thin]
    ind = report.get("indicators", {})
    lines.append(f"Nodes : {ind.get('node_count', 0)}")
    lines.append(f"Edges : {ind.get('edge_count', 0)}")
    lines.append("")

    lines += [thin, "IDENTITY ANALYSIS", thin]
    ident = report.get("identity_analysis", {})
    lines.append(f"Display Name : {ident.get('display_name')}")
    lines.append(f"From Domain  : {ident.get('from_domain')}")
    lines.append(f"Reply-To Domain    : {ident.get('reply_to_domain')}")
    lines.append(f"Return-Path Domain : {ident.get('return_path_domain')}")
    for f in ident.get("findings", []):
        lines.append(f"  - [{f.get('severity', '?')}] {f.get('finding', '?')}")
    lines.append("")

    lines += [thin, "RECEIVED CHAIN", thin]
    rc = report.get("received_chain", {})
    lines.append(f"Hop count : {rc.get('hop_count', 0)}")
    for hop in rc.get("chain", []):
        lines.append(
            f"  Hop {hop.get('hop_number', '?')}: host={hop.get('hostname')} "
            f"ip={hop.get('ip')} [{hop.get('classification', '?')}]"
        )
    lines.append("")

    lines += [thin, "CAMPAIGN RELATIONSHIPS", thin]
    camp = report.get("campaign_relationships", {})
    if camp.get("is_part_of_campaign"):
        lines.append(f"Campaign ID          : {camp.get('campaign_id')}")
        lines.append(f"Related emails       : {camp.get('related_email_count', 0)}")
        lines.append(f"Shared indicators    : {camp.get('shared_indicators', {})}")
        lines.append(f"Correlation score    : {camp.get('correlation_score')}")
        lines.append(f"Confidence           : {camp.get('confidence')}")
    else:
        lines.append(camp.get("note", "Not part of a correlated campaign."))
    lines.append("")

    lines += [thin, "LIMITATIONS", thin]
    for lim in report.get("limitations", []):
        lines.append("  - " + textwrap.fill(lim, width=56, subsequent_indent="    "))
    lines.append("")

    lines += [thin, "ANALYST NOTES", thin]
    for note in report.get("analyst_notes", []):
        lines.append("  - " + textwrap.fill(note, width=56, subsequent_indent="    "))
    lines.append("")

    lines += [sep, f"TRACE-X {PIPELINE_VERSION} - {report.get('report_version')}", sep]
    return "\n".join(lines)
