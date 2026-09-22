"""
M09 — Threat Graph

Builds a node/edge graph plus threat-pattern detection and threat
classification from the REAL M07 EvidenceBundle and M08 RiskAssessment dict
schemas used in this project (evidence items keyed by "source", e.g.
"identity:lookalike_domain"; risk factors carrying "source",
"effective_weight", "correlation_group").

Design principles (same as M01-M08):
- Graph is built only from evidence actually present - nothing invented.
- Every node/edge is traceable to a source evidence tag and module.
- Threat patterns are explicit, documented rules - not a black box.
- All upstream data is treated as untrusted input; nothing here crashes
  on missing/malformed fields.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

# ---------------------------------------------------------------------------
# Map each M02-M06 evidence "source" tag to a canonical signal type. This is
# the same vocabulary used for M08's CORRELATION_GROUPS, extended to cover
# every source tag actually emitted by the analyzers.
# ---------------------------------------------------------------------------
SOURCE_TO_SIGNAL: Dict[str, str] = {
    "geo:origin_country": "INFRASTRUCTURE_COUNTRY",
    "geo:private_ip_hop": "PRIVATE_INFRASTRUCTURE_HOP",
    "identity:lookalike_domain": "LOOKALIKE_DOMAIN",
    "identity:homoglyph_lookalike": "LOOKALIKE_DOMAIN",
    "identity:punycode_domain": "LOOKALIKE_DOMAIN",
    "identity:display_name_brand_impersonation": "FROM_DISPLAY_SPOOFING",
    "identity:display_name_contains_address": "FROM_DISPLAY_SPOOFING",
    "identity:reply_to_domain_mismatch": "REPLY_TO_MISMATCH",
    "header:reply_to_vs_from": "REPLY_TO_MISMATCH",
    "header:return_path_vs_from": "SENDER_DOMAIN_MISMATCH",
    "url:structural_analysis": "SUSPICIOUS_URL",
    "auth:spf_fail": "SPF_FAIL",
    "auth:dkim_weak": "DKIM_FAIL",
    "auth:dmarc_weak": "DMARC_FAIL",
    "auth:alignment_mismatch": "SENDER_DOMAIN_MISMATCH",
    "auth:header_manipulation_suspected": "HEADER_ANOMALY",
    "auth:missing_header": "AUTH_MISSING",
    "header:message_id_domain_anomaly": "HEADER_ANOMALY",
    "header:nonstandard_auth_header": "HEADER_ANOMALY",
    "header:from_multiple_at": "HEADER_ANOMALY",
    "header:date_malformed": "HEADER_ANOMALY",
    "header:from_missing": "HEADER_ANOMALY",
    "header:date_missing": "HEADER_ANOMALY",
    "header:received_missing": "RECEIVED_CHAIN_ANOMALY",
    "received:no_hops": "RECEIVED_CHAIN_ANOMALY",
    "received:earliest_hop_uncertain": "RECEIVED_CHAIN_ANOMALY",
    "received:private_ip_as_origin": "RECEIVED_CHAIN_ANOMALY",
    "received:excessive_hops": "RECEIVED_CHAIN_ANOMALY",
}

NODE_TYPE_FOR_SIGNAL: Dict[str, str] = {
    "INFRASTRUCTURE_COUNTRY": "INFRASTRUCTURE",
    "PRIVATE_INFRASTRUCTURE_HOP": "INFRASTRUCTURE",
    "LOOKALIKE_DOMAIN": "DOMAIN",
    "SENDER_DOMAIN_MISMATCH": "DOMAIN",
    "FROM_DISPLAY_SPOOFING": "EMAIL_ADDRESS",
    "REPLY_TO_MISMATCH": "EMAIL_ADDRESS",
    "SUSPICIOUS_URL": "URL",
    "SPF_FAIL": "INFRASTRUCTURE",
    "DKIM_FAIL": "INFRASTRUCTURE",
    "DMARC_FAIL": "INFRASTRUCTURE",
    "AUTH_MISSING": "INFRASTRUCTURE",
    "HEADER_ANOMALY": "INFRASTRUCTURE",
    "RECEIVED_CHAIN_ANOMALY": "INFRASTRUCTURE",
}

EDGE_TYPE_FOR_SIGNAL: Dict[str, str] = {
    "INFRASTRUCTURE_COUNTRY": "OBSERVED_AT_INFRASTRUCTURE",
    "PRIVATE_INFRASTRUCTURE_HOP": "ROUTED_THROUGH",
    "LOOKALIKE_DOMAIN": "IMPERSONATES",
    "SENDER_DOMAIN_MISMATCH": "SENDS_FROM",
    "FROM_DISPLAY_SPOOFING": "IMPERSONATES",
    "REPLY_TO_MISMATCH": "REPLY_TO",
    "SUSPICIOUS_URL": "ASSOCIATED_WITH",
    "SPF_FAIL": "ASSOCIATED_WITH",
    "DKIM_FAIL": "ASSOCIATED_WITH",
    "DMARC_FAIL": "ASSOCIATED_WITH",
    "AUTH_MISSING": "ASSOCIATED_WITH",
    "HEADER_ANOMALY": "ASSOCIATED_WITH",
    "RECEIVED_CHAIN_ANOMALY": "SENDS_FROM",
}

NODE_LABELS: Dict[str, str] = {
    "INFRASTRUCTURE_COUNTRY": "Probable infrastructure country",
    "PRIVATE_INFRASTRUCTURE_HOP": "Internal/non-routable mail hop",
    "LOOKALIKE_DOMAIN": "Look-alike / Spoofed Domain",
    "SENDER_DOMAIN_MISMATCH": "Sender Domain Mismatch",
    "FROM_DISPLAY_SPOOFING": "Display Name Spoofing",
    "REPLY_TO_MISMATCH": "Suspicious Reply-To",
    "SUSPICIOUS_URL": "Suspicious URL",
    "SPF_FAIL": "SPF Failure",
    "DKIM_FAIL": "DKIM Failure",
    "DMARC_FAIL": "DMARC Failure",
    "AUTH_MISSING": "Authentication Data Missing",
    "HEADER_ANOMALY": "Header Anomaly",
    "RECEIVED_CHAIN_ANOMALY": "Received-Chain Anomaly",
}


@dataclass(frozen=True)
class _PatternRule:
    pattern_id: str
    name: str
    description: str
    required: frozenset
    any_of: frozenset
    indicates: str
    severity: str
    confidence: str


_PATTERN_RULES: List[_PatternRule] = [
    _PatternRule(
        "IDENTITY_DECEPTION", "Identity Deception",
        "A look-alike/spoofed domain combined with a reply-to, display-name, "
        "or sender-domain mismatch indicates deliberate identity deception.",
        frozenset({"LOOKALIKE_DOMAIN"}),
        frozenset({"REPLY_TO_MISMATCH", "FROM_DISPLAY_SPOOFING", "SENDER_DOMAIN_MISMATCH"}),
        "PHISHING", "HIGH", "HIGH",
    ),
    _PatternRule(
        "REPLY_TO_REDIRECT", "Reply-To Redirect",
        "The Reply-To address differs from the From address, redirecting "
        "replies elsewhere. Common in BEC and phishing.",
        frozenset({"REPLY_TO_MISMATCH"}), frozenset(),
        "BEC", "HIGH", "MEDIUM",
    ),
    _PatternRule(
        "BEC_EXECUTIVE_IMPERSONATION", "BEC Executive Impersonation",
        "Display-name spoofing combined with a Reply-To redirect is the "
        "primary pattern in Business Email Compromise attacks.",
        frozenset({"FROM_DISPLAY_SPOOFING", "REPLY_TO_MISMATCH"}), frozenset(),
        "BEC", "CRITICAL", "HIGH",
    ),
    _PatternRule(
        "BRAND_IMPERSONATION_PHISHING", "Brand Impersonation Phishing",
        "Display-name brand impersonation combined with a suspicious URL or "
        "an authentication failure indicates a phishing attempt trading on a "
        "trusted brand's identity, even without a registered look-alike domain.",
        frozenset({"FROM_DISPLAY_SPOOFING"}),
        frozenset({"SUSPICIOUS_URL", "SPF_FAIL", "DMARC_FAIL"}),
        "PHISHING", "HIGH", "HIGH",
    ),
    _PatternRule(
        "AUTH_BYPASS_SPOOFING", "Authentication Bypass with Spoofing",
        "A sender-domain mismatch combined with an authentication failure "
        "suggests infrastructure not authorised by the domain owner.",
        frozenset({"SENDER_DOMAIN_MISMATCH"}),
        frozenset({"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"}),
        "SPOOFING", "HIGH", "HIGH",
    ),
    _PatternRule(
        "COORDINATED_PHISHING", "Coordinated Phishing Campaign",
        "Identity deception combined with a suspicious URL and either a "
        "reply-to mismatch or DMARC failure indicates a coordinated, "
        "multi-vector phishing attempt.",
        frozenset({"LOOKALIKE_DOMAIN", "SUSPICIOUS_URL"}),
        frozenset({"REPLY_TO_MISMATCH", "DMARC_FAIL"}),
        "PHISHING", "CRITICAL", "HIGH",
    ),
    _PatternRule(
        "INFRASTRUCTURE_ABUSE", "Infrastructure Abuse",
        "Received-chain anomalies combined with other header anomalies "
        "suggest routing through unauthorised or misconfigured infrastructure.",
        frozenset({"RECEIVED_CHAIN_ANOMALY"}), frozenset({"HEADER_ANOMALY"}),
        "INFRASTRUCTURE_ABUSE", "MEDIUM", "MEDIUM",
    ),
    _PatternRule(
        "AUTH_FAILURE_ONLY", "Authentication Failure",
        "One or more authentication mechanisms failed. Without additional "
        "identity or URL signals this may indicate misconfiguration rather "
        "than an active threat.",
        frozenset({"SPF_FAIL"}), frozenset({"DKIM_FAIL", "DMARC_FAIL"}),
        "SPOOFING", "MEDIUM", "LOW",
    ),
]

_THREAT_CLASS_PRIORITY = {
    "BEC": 5, "PHISHING": 4, "SPOOFING": 3, "INFRASTRUCTURE_ABUSE": 2,
    "UNKNOWN": 0, "CLEAN": 0,
}


def _active_signals(risk: dict) -> Dict[str, dict]:
    """Map canonical signal -> the strongest risk_factor that produced it."""
    active: Dict[str, dict] = {}
    for rf in risk.get("risk_factors", []):
        signal = SOURCE_TO_SIGNAL.get(rf.get("source"))
        if not signal:
            continue
        existing = active.get(signal)
        if existing is None or rf.get("effective_weight", 0) > existing.get("effective_weight", 0):
            active[signal] = rf
    return active


def _detect_patterns(active_types: Set[str]) -> List[dict]:
    matched = []
    for rule in _PATTERN_RULES:
        if not rule.required.issubset(active_types):
            continue
        if rule.any_of and not rule.any_of.intersection(active_types):
            continue
        matched_on = sorted(rule.required.union(rule.any_of.intersection(active_types)))
        matched.append({
            "pattern_id": rule.pattern_id,
            "name": rule.name,
            "description": rule.description,
            "matched_on": matched_on,
            "confidence": rule.confidence,
            "severity": rule.severity,
            "indicates": rule.indicates,
        })
    return matched


def _classify(patterns: List[dict], risk_score: int, active_types: Set[str]) -> tuple:
    reasons: List[str] = []
    if risk_score == 0 or not active_types:
        reasons.append("No risk-bearing evidence present - classified as CLEAN.")
        return "CLEAN", "HIGH", reasons

    if not patterns:
        reasons.append("Evidence present but no recognised threat pattern matched.")
        confidence = "LOW"
        if risk_score >= 45:
            reasons.append(f"Risk score {risk_score} is significant - manual review recommended.")
        return "UNKNOWN", confidence, reasons

    best = max(
        patterns,
        key=lambda p: (_THREAT_CLASS_PRIORITY.get(p["indicates"], 0),
                        {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(p["severity"], 0)),
    )
    threat_class = best["indicates"]
    confidence = best["confidence"]
    reasons.append(f"Primary pattern: {best['name']} - {best['description']}")

    others = [p["name"] for p in patterns if p["pattern_id"] != best["pattern_id"]]
    if others:
        reasons.append(f"{len(others)} additional pattern(s) also matched: {', '.join(others)}.")

    if risk_score < 20:
        confidence = "LOW"
        reasons.append("Pattern matched but risk score is LOW - confidence reduced.")
    elif risk_score < 45 and confidence == "HIGH":
        confidence = "MEDIUM"
        reasons.append("Confidence adjusted to MEDIUM - risk score is in the MEDIUM range.")

    return threat_class, confidence, reasons


def build_threat_graph(evidence_bundle: dict, risk: dict, email_id: str = "unknown-email") -> dict:
    """Build the threat graph and classification from real M07/M08 output."""
    evidence_bundle = evidence_bundle or {"evidence": [], "evidence_count": 0}
    risk = risk or {"score": 0, "risk_level": "LOW", "risk_factors": [], "confidence": "LOW"}
    email_id = email_id or "unknown-email"

    nodes: List[dict] = []
    edges: List[dict] = []

    email_node_id = str(uuid.uuid4())
    risk_score = risk.get("score", 0)
    risk_level = risk.get("risk_level", "LOW")

    nodes.append({
        "node_id": email_node_id,
        "node_type": "EMAIL_ADDRESS",
        "value": email_id,
        "label": f"Email: {email_id}",
        "source_module": "m08_risk_engine",
        "risk_bearing": risk_score > 0,
        "attributes": {"risk_score": risk_score, "risk_level": risk_level},
    })

    active = _active_signals(risk)

    for signal, rf in active.items():
        node_id = str(uuid.uuid4())
        node_type = NODE_TYPE_FOR_SIGNAL.get(signal, "UNKNOWN")
        nodes.append({
            "node_id": node_id,
            "node_type": node_type,
            "value": signal,
            "label": NODE_LABELS.get(signal, signal),
            "source_module": rf.get("module"),
            "evidence_id": rf.get("evidence_id"),
            "risk_bearing": True,
            "attributes": {
                "severity": rf.get("severity"),
                "effective_weight": rf.get("effective_weight"),
                "finding": rf.get("finding"),
                "source": rf.get("source"),
                "evidence": next((e.get("evidence") for e in evidence_bundle.get("evidence", []) if e.get("evidence_id") == rf.get("evidence_id")), None),
            },
        })
        edge_type = EDGE_TYPE_FOR_SIGNAL.get(signal, "ASSOCIATED_WITH")
        edges.append({
            "edge_id": str(uuid.uuid4()),
            "edge_type": edge_type,
            "source_node": email_node_id,
            "target_node": node_id,
            "label": edge_type.replace("_", " ").lower(),
            "confidence": "HIGH" if rf.get("severity") in ("HIGH", "CRITICAL") else "MEDIUM",
            "source_module": rf.get("module"),
        })

    # Preserve non-risk-bearing M17 country observations as infrastructure
    # nodes. They enrich correlation without inflating M08 risk scores.
    for evidence in evidence_bundle.get("evidence", []):
        if evidence.get("source") != "geo:origin_country":
            continue
        node_id = str(uuid.uuid4())
        nodes.append({"node_id": node_id, "node_type": "INFRASTRUCTURE",
                      "value": evidence.get("evidence"), "label": "Probable infrastructure country",
                      "source_module": evidence.get("module"), "evidence_id": evidence.get("evidence_id"),
                      "risk_bearing": False,
                      "attributes": {"source": evidence.get("source"), "evidence": evidence.get("evidence"),
                                     "confidence": evidence.get("confidence")}})
        edges.append({"edge_id": str(uuid.uuid4()), "edge_type": "OBSERVED_AT_INFRASTRUCTURE",
                      "source_node": email_node_id, "target_node": node_id,
                      "label": "observed at probable infrastructure", "confidence": evidence.get("confidence", "MEDIUM"),
                      "source_module": evidence.get("module")})

    active_types = set(active.keys())
    threat_patterns = _detect_patterns(active_types)
    threat_class, threat_class_confidence, threat_class_reasons = _classify(
        threat_patterns, risk_score, active_types,
    )

    if threat_class == "CLEAN":
        summary = (
            f"No threat indicators detected. Graph contains {len(nodes)} node(s) "
            f"and {len(edges)} edge(s). Risk: {risk_level} ({risk_score}/100)."
        )
    else:
        pattern_names = ", ".join(p["name"] for p in threat_patterns) or "none"
        summary = (
            f"Threat classification: {threat_class}. Risk: {risk_level} ({risk_score}/100). "
            f"Pattern(s) detected: {pattern_names}. Graph: {len(nodes)} node(s), {len(edges)} edge(s)."
        )

    return {
        "graph_id": str(uuid.uuid4()),
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "threat_patterns": threat_patterns,
        "threat_class": threat_class,
        "threat_class_confidence": threat_class_confidence,
        "threat_class_reasons": threat_class_reasons,
        "summary": summary,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "built_at": datetime.now(timezone.utc).isoformat(),
    }


def build_sender_trust_graph(feedback_records: list, sender: str, content_signal_present: bool = False) -> dict:
    """Build an offline relationship graph from explicit analyst outcomes only.

    No feedback history is treated as unknown, never as malicious. A first-seen
    signal is emitted only when a separate payment/credential content signal is present.
    """
    nodes, edges, legitimate, malicious = [], [], 0, 0
    sender_norm = (sender or "").strip().lower()
    for raw in feedback_records or []:
        record = raw.to_dict() if hasattr(raw, "to_dict") else raw
        details = record.get("details") or {}
        observed = str(details.get("sender") or details.get("from_address") or "").strip().lower()
        if not observed or observed != sender_norm:
            continue
        decision = record.get("decision_type")
        if decision in {"TRUSTED_SENDER", "BENIGN_BUSINESS_EMAIL"}: legitimate += 1
        if decision in {"SUSPICIOUS_SENDER_CONFIRMED", "THREAT_ESCALATED", "FALSE_NEGATIVE"}: malicious += 1
        edges.append({"edge_type": "ANALYST_CONFIRMED_OUTCOME", "sender": sender_norm,
                      "decision_type": decision, "feedback_id": record.get("feedback_id")})
    if sender_norm:
        nodes.append({"node_type": "SENDER", "value": sender_norm,
                      "attributes": {"confirmed_legitimate": legitimate, "confirmed_malicious": malicious}})
    findings = []
    if sender_norm and legitimate == 0 and content_signal_present:
        findings.append({"finding_id": "TRUST-001", "finding": "No prior confirmed-legitimate correlation for sender",
                         "severity": "MEDIUM", "evidence": f"sender={sender_norm}; confirmed_legitimate=0; paired_content_signal=true",
                         "source": "trust:first_seen_sensitive_request", "confidence": "MEDIUM", "category": "RELATIONSHIP",
                         "module": "M09_TRUST_GRAPH"})
    return {"nodes": nodes, "edges": edges, "findings": findings,
            "summary": {"sender": sender_norm, "confirmed_legitimate": legitimate, "confirmed_malicious": malicious},
            "limitations": ["Only explicit analyst feedback supplied to this call is used.",
                            "Absence of history is unknown, not proof of malice."]}


# ===========================================================================
# M09 — Campaign Correlation
#
# Given multiple already-analyzed investigations (each the full dict
# produced by core.pipeline.analyze_email), find groups of emails that
# share REAL, OBSERVED indicators (sender domain, Reply-To domain, URL
# host, display name, near-identical subject). Emails are only ever
# grouped into a campaign because of a concrete shared indicator that is
# reported alongside the grouping -- nothing is invented, and no campaign
# is claimed on the basis of "feels similar".
# ===========================================================================
import hashlib
import re


# Documented, fixed points-per-indicator-type used only to produce a
# transparent, explainable correlation score. Not an ML model; a simple,
# auditable rule: each DISTINCT type of shared indicator observed across a
# cluster adds a fixed amount, capped at 100.
_CAMPAIGN_INDICATOR_POINTS = {
    "shared_sender_domain": 40,
    "shared_url_host": 35,
    "shared_reply_to_domain": 20,
    "shared_display_name": 15,
    "similar_subject_pattern": 10,
}


def _normalize_subject(subject: str) -> str:
    """Strip reply/forward prefixes and digits so 'Account limited #1' and
    'Account limited #2' are recognised as the same underlying pattern."""
    if not subject:
        return ""
    s = subject.lower()
    s = re.sub(r"^(re|fwd?)\s*:\s*", "", s)
    s = re.sub(r"\d+", "", s)
    s = re.sub(r"[^a-z\s]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _extract_campaign_signals(investigation: dict) -> dict:
    """Pull only real, already-computed values out of an investigation
    result -- no new analysis, no invented data."""
    identity = investigation.get("identity") or {}
    url_analysis = investigation.get("url_analysis") or {}
    email_summary = investigation.get("email_summary") or {}

    url_hosts = {
        (u.get("host") or "").lower()
        for u in url_analysis.get("urls", [])
        if u.get("host")
    }

    return {
        "investigation_id": investigation.get("investigation_id"),
        "file": investigation.get("file"),
        "sender_domain": (identity.get("from_domain") or "").lower(),
        "reply_to_domain": (identity.get("reply_to_domain") or "").lower(),
        "display_name": (identity.get("display_name") or "").strip().lower(),
        "url_hosts": url_hosts,
        "subject_pattern": _normalize_subject(email_summary.get("subject") or ""),
    }


def _shared_indicators_between(a: dict, b: dict) -> Dict[str, Any]:
    """Return only the indicators that ACTUALLY match between two emails'
    signal sets. Empty/falsy values never count as a match."""
    shared: Dict[str, Any] = {}

    if a["sender_domain"] and a["sender_domain"] == b["sender_domain"]:
        shared["shared_sender_domain"] = a["sender_domain"]

    if a["reply_to_domain"] and a["reply_to_domain"] == b["reply_to_domain"]:
        shared["shared_reply_to_domain"] = a["reply_to_domain"]

    if a["display_name"] and a["display_name"] == b["display_name"]:
        shared["shared_display_name"] = a["display_name"]

    common_hosts = a["url_hosts"] & b["url_hosts"]
    if common_hosts:
        shared["shared_url_host"] = sorted(common_hosts)

    if a["subject_pattern"] and len(a["subject_pattern"]) >= 6 and a["subject_pattern"] == b["subject_pattern"]:
        shared["similar_subject_pattern"] = a["subject_pattern"]

    return shared


def _union_find_find(parent: Dict[str, str], x: str) -> str:
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def _union_find_union(parent: Dict[str, str], a: str, b: str) -> None:
    ra, rb = _union_find_find(parent, a), _union_find_find(parent, b)
    if ra != rb:
        parent[ra] = rb


def correlate_campaign(investigations: List[dict]) -> dict:
    """
    Compare multiple analyzed investigations and group them into campaigns
    based on real, shared, observable indicators.

    Returns:
        {
          "total_investigations": int,
          "campaigns": [
              {
                "campaign_id": "CAMP-xxxxxxxx",
                "related_emails": [{"investigation_id", "file"}, ...],
                "shared_indicators": {indicator_type: value(s), ...},
                "correlation_signals": [indicator_type, ...],
                "correlation_score": 0-100,
                "confidence": "LOW"|"MEDIUM"|"HIGH",
                "evidence": ["Shared domain: x.com (present in TX-1, TX-2)", ...],
              },
              ...
          ],
          "uncorrelated": ["TX-000003", ...],
        }

    An email is placed in a campaign ONLY if it shares at least one real
    indicator with at least one other email in the batch. Unrelated
    (including entirely legitimate) emails are correctly left uncorrelated.
    """
    if not investigations:
        return {"total_investigations": 0, "campaigns": [], "uncorrelated": []}

    signals = [_extract_campaign_signals(inv) for inv in investigations]
    ids = [s["investigation_id"] for s in signals]

    parent = {i: i for i in ids}
    pair_shared: Dict[frozenset, Dict[str, Any]] = {}

    for i in range(len(signals)):
        for j in range(i + 1, len(signals)):
            a, b = signals[i], signals[j]
            shared = _shared_indicators_between(a, b)
            if shared:
                _union_find_union(parent, a["investigation_id"], b["investigation_id"])
                pair_shared[frozenset((a["investigation_id"], b["investigation_id"]))] = shared

    clusters: Dict[str, List[str]] = {}
    for inv_id in ids:
        root = _union_find_find(parent, inv_id)
        clusters.setdefault(root, []).append(inv_id)

    campaigns = []
    uncorrelated = []

    for root, members in clusters.items():
        if len(members) < 2:
            uncorrelated.extend(members)
            continue

        members_sorted = sorted(members)
        member_signal_by_id = {s["investigation_id"]: s for s in signals}

        # Aggregate concrete values and the exact members that support each
        # value. Connected-component grouping may be transitive (A shares one
        # indicator with B; B shares a different one with C), so it would be
        # false to claim every indicator was observed across every member.
        aggregated: Dict[str, Set[str]] = {}
        support: Dict[str, Dict[str, Set[str]]] = {}
        evidence: List[str] = []
        for k in range(len(members_sorted)):
            for l in range(k + 1, len(members_sorted)):
                left, right = members_sorted[k], members_sorted[l]
                shared = pair_shared.get(frozenset((left, right)))
                if not shared:
                    continue
                for indicator_type, value in shared.items():
                    values = value if isinstance(value, list) else [value]
                    aggregated.setdefault(indicator_type, set()).update(values)
                    by_value = support.setdefault(indicator_type, {})
                    for concrete in values:
                        by_value.setdefault(concrete, set()).update((left, right))

        for indicator_type, values in sorted(aggregated.items()):
            label = indicator_type.replace("_", " ")
            for value in sorted(values):
                supported_by = sorted(support[indicator_type][value])
                evidence.append(
                    f"{label}: {value} (observed in {len(supported_by)} email(s): "
                    f"{', '.join(supported_by)})"
                )

        correlation_signals = sorted(aggregated.keys())
        correlation_score = min(
            100, sum(_CAMPAIGN_INDICATOR_POINTS.get(sig, 0) for sig in correlation_signals)
        )

        if len(correlation_signals) >= 2:
            confidence = "HIGH"
        elif len(correlation_signals) == 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"  # unreachable in practice (cluster requires >=1 shared indicator)

        campaign_id = "CAMP-" + hashlib.sha256(
            "|".join(members_sorted).encode("utf-8")
        ).hexdigest()[:8]

        campaigns.append({
            "campaign_id": campaign_id,
            "related_emails": [
                {"investigation_id": mid, "file": member_signal_by_id[mid]["file"]}
                for mid in members_sorted
            ],
            "related_email_count": len(members_sorted),
            "shared_indicators": {k: sorted(v) for k, v in aggregated.items()},
            "indicator_support": {
                indicator_type: {value: sorted(member_ids) for value, member_ids in sorted(by_value.items())}
                for indicator_type, by_value in sorted(support.items())
            },
            "correlation_signals": correlation_signals,
            "correlation_score": correlation_score,
            "confidence": confidence,
            "evidence": evidence,
        })

    campaigns.sort(key=lambda c: c["campaign_id"])
    return {
        "total_investigations": len(investigations),
        "campaigns": campaigns,
        "uncorrelated": sorted(uncorrelated),
    }
