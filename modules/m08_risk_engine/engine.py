"""
M08 — Risk Engine

Transparent, rule-based scoring over the M07 EvidenceBundle. Produces a
documented score (0-100), a risk level (LOW/MEDIUM/HIGH/CRITICAL), the
contributing risk factors, an explanation, and an overall confidence.

No arbitrary unexplained weights: every point added is attributable to a
specific evidence item and a documented per-severity weight below.
"""
from typing import Dict, List

from core.config import RISK_THRESHOLDS

# Documented, fixed weights per severity level. These are the ONLY numbers
# used to compute score contributions -- nothing hidden, nothing invented.
SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 9,
    "LOW": 3,
    "INFO": 0,
}

# Diminishing-returns cap per severity bucket, so 10 LOW findings don't
# outweigh a single CRITICAL. Documented explicitly.
MAX_CONTRIBUTION_PER_SEVERITY = {
    "CRITICAL": 60,
    "HIGH": 45,
    "MEDIUM": 27,
    "LOW": 12,
    "INFO": 0,
}

# ---- Evidence correlation groups ----
# Exact duplicate (finding + evidence) items are already merged upstream by
# M07. But distinct findings can still be *strongly related* -- e.g. a
# Reply-To mismatch (M02) and a Reply-To domain mismatch (M04) are two
# observations of essentially the same underlying signal. Counting both at
# full weight artificially inflates the score. Each evidence "source" tag is
# assigned to a correlation group below; within a group, only the
# highest-weight item counts at full strength and subsequent items in the
# same group contribute at a documented, geometrically diminishing rate
# (50% of the previous item's weight, floor of 1 point). Items with no group
# mapping ("UNGROUPED") are treated as fully independent and always retain
# their full weight.
CORRELATION_GROUPS = {
    # IDENTITY / sender-domain mismatch family (Reply-To, Return-Path vs From)
    "header:reply_to_vs_from": "IDENTITY_MISMATCH",
    "header:return_path_vs_from": "IDENTITY_MISMATCH",
    "identity:reply_to_domain_mismatch": "IDENTITY_MISMATCH",

    # IDENTITY / display or domain spoofing family
    "identity:display_name_brand_impersonation": "IDENTITY_SPOOFING",
    "identity:display_name_contains_address": "IDENTITY_SPOOFING",
    "identity:lookalike_domain": "IDENTITY_SPOOFING",
    "identity:homoglyph_lookalike": "IDENTITY_SPOOFING",
    "identity:punycode_domain": "IDENTITY_SPOOFING",

    # URL risk family
    "url:structural_analysis": "URL_RISK",

    # AUTHENTICATION failure family (SPF/DKIM/DMARC/alignment/manipulation)
    "auth:spf_fail": "AUTH_FAILURE",
    "auth:dkim_weak": "AUTH_FAILURE",
    "auth:dmarc_weak": "AUTH_FAILURE",
    "auth:alignment_mismatch": "AUTH_FAILURE",
    "auth:header_manipulation_suspected": "AUTH_FAILURE",

    # HEADER anomaly family
    "header:message_id_domain_anomaly": "HEADER_ANOMALY",
    "header:nonstandard_auth_header": "HEADER_ANOMALY",
    "header:from_multiple_at": "HEADER_ANOMALY",
    "header:date_malformed": "HEADER_ANOMALY",

    # RECEIVED-chain anomaly family
    "received:earliest_hop_uncertain": "RECEIVED_CHAIN_ANOMALY",
    "received:private_ip_as_origin": "RECEIVED_CHAIN_ANOMALY",
    "received:excessive_hops": "RECEIVED_CHAIN_ANOMALY",

    # Offline infrastructure intelligence family. Country resolution is INFO-only;
    # future independently supported infrastructure anomalies share this bucket.
    "geo:private_ip_hop": "INFRASTRUCTURE_ANOMALY",
    "geo:hosting_asn": "INFRASTRUCTURE_ANOMALY",
    "trust:first_seen_sensitive_request": "SENDER_TRUST_ANOMALY",
}

# Diminishing-contribution ratio applied to the 2nd, 3rd, ... item within the
# same correlation group (geometric decay). Documented, fixed, not tuned.
GROUP_DECAY_RATIO = 0.5
GROUP_MIN_CONTRIBUTION = 1


def _apply_correlation_decay(risk_factors: List[Dict]) -> List[Dict]:
    """Given risk_factors (each with 'weight' and 'source'), returns a new
    list of dicts with an added 'effective_weight' field: the full weight
    for the strongest item in each correlation group, and a documented
    diminishing weight for every subsequent item in that same group.
    Ungrouped items always keep their full weight (independent evidence)."""
    by_group: Dict[str, List[Dict]] = {}
    ungrouped: List[Dict] = []

    for rf in risk_factors:
        group = CORRELATION_GROUPS.get(rf["source"])
        if group is None:
            ungrouped.append(rf)
        else:
            by_group.setdefault(group, []).append(rf)

    adjusted: List[Dict] = []

    for rf in ungrouped:
        rf = dict(rf)
        rf["effective_weight"] = rf["weight"]
        rf["correlation_group"] = "UNGROUPED"
        adjusted.append(rf)

    for group, items in by_group.items():
        # Strongest evidence in the group counts fully; related items decay.
        items_sorted = sorted(items, key=lambda x: x["weight"], reverse=True)
        for idx, rf in enumerate(items_sorted):
            rf = dict(rf)
            rf["correlation_group"] = group
            if idx == 0:
                rf["effective_weight"] = rf["weight"]
            else:
                decayed = rf["weight"] * (GROUP_DECAY_RATIO ** idx)
                rf["effective_weight"] = max(GROUP_MIN_CONTRIBUTION, round(decayed))
            adjusted.append(rf)

    return adjusted


def _score_level(score: int) -> str:
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def compute_risk(evidence_bundle: dict) -> dict:
    evidence_items = evidence_bundle.get("evidence", [])

    contributions_by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    risk_factors: List[Dict] = []

    for item in evidence_items:
        sev = item["severity"]
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        if weight > 0:
            factor = {
                "evidence_id": item["evidence_id"],
                "finding": item["finding"],
                "severity": sev,
                "weight": weight,
                "module": item["module"],
                "source": item["source"],
            }
            if item.get("module") == "M03_AUTH_ANALYZER":
                factor["authentication_provenance"] = item.get(
                    "authentication_provenance",
                    {
                        "verification_state": "REPORTED_UNVERIFIED",
                        "independently_verified": False,
                        "trusted_source": False,
                    },
                )
                factor["automated_prevention_eligible"] = bool(
                    item.get("automated_prevention_eligible", False)
                )
            risk_factors.append(factor)

    # Step 1: correlate related evidence and compute a per-item effective
    # (post-decay) weight, so strongly related signals don't inflate the
    # score while independent evidence keeps its full contribution.
    risk_factors = _apply_correlation_decay(risk_factors)

    for rf in risk_factors:
        contributions_by_severity[rf["severity"]] += rf["effective_weight"]

    # Step 2: apply documented per-severity caps (diminishing returns) as a
    # secondary, independent safety net on top of correlation decay.
    capped_total = 0
    capped_breakdown = {}
    for sev, raw_total in contributions_by_severity.items():
        cap = MAX_CONTRIBUTION_PER_SEVERITY.get(sev, 0)
        capped = min(raw_total, cap)
        capped_breakdown[sev] = {"raw": raw_total, "capped": capped, "cap": cap}
        capped_total += capped

    score = min(100, capped_total)
    level = _score_level(score)

    # Confidence: HIGH if we have multiple corroborating high-severity items
    # from more than one distinct module; otherwise MEDIUM/LOW.
    high_sev_modules = {rf["module"] for rf in risk_factors if rf["severity"] in ("CRITICAL", "HIGH")}
    if len(high_sev_modules) >= 2:
        confidence = "HIGH"
    elif len(high_sev_modules) == 1:
        confidence = "MEDIUM"
    elif risk_factors:
        confidence = "LOW"
    else:
        confidence = "LOW"

    explanation_parts = []
    if score == 0:
        explanation_parts.append("No risk-contributing findings were identified across any analysis module.")
    else:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = sum(1 for rf in risk_factors if rf["severity"] == sev)
            if n:
                explanation_parts.append(f"{n} {sev.lower()}-severity finding(s) contributing {capped_breakdown[sev]['capped']} point(s) (capped at {capped_breakdown[sev]['cap']}).")
    explanation = " ".join(explanation_parts)

    # Sort risk factors by effective (post-correlation) weight desc for readability
    risk_factors.sort(key=lambda rf: rf["effective_weight"], reverse=True)

    untrusted_auth_evidence_ids = [
        rf["evidence_id"]
        for rf in risk_factors
        if rf.get("module") == "M03_AUTH_ANALYZER"
        and not rf.get("automated_prevention_eligible", False)
    ]
    trusted_auth_evidence_ids = [
        rf["evidence_id"]
        for rf in risk_factors
        if rf.get("module") == "M03_AUTH_ANALYZER"
        and rf.get("automated_prevention_eligible", False)
    ]

    return {
        "score": score,
        "risk_level": level,
        "confidence": confidence,
        "risk_factors": risk_factors,
        "score_breakdown": capped_breakdown,
        "explanation": explanation,
        "prevention_constraints": {
            "untrusted_reported_authentication_evidence_ids": untrusted_auth_evidence_ids,
            "trusted_source_authentication_evidence_ids": trusted_auth_evidence_ids,
            "untrusted_authentication_may_support_automated_action": False,
            "note": (
                "Risk scoring preserves reported authentication observations for "
                "forensic review. Authentication evidence from an untrusted source "
                "must not support automated prevention action. A trusted source is "
                "still reported-header evidence, not independent SPF/DKIM/DMARC verification."
            ),
        },
        "scoring_method": (
            "Rule-based, additive scoring. Each evidence item contributes a fixed, "
            "documented weight based on its severity (CRITICAL=30, HIGH=18, MEDIUM=9, "
            "LOW=3, INFO=0). Exact duplicate findings are merged upstream (M07). "
            "Distinct but strongly related findings (same CORRELATION_GROUPS bucket, "
            "e.g. multiple identity-mismatch or authentication-failure signals) are "
            "de-inflated: the strongest item in a group counts at full weight, each "
            "additional related item decays geometrically (50% of the prior item's "
            "weight, floor of 1 point). Independent evidence from unrelated sources "
            "always retains full weight. Contributions are then capped per severity "
            "bucket to prevent high volumes of low-severity findings from dominating "
            "the score. Final score is the sum of capped per-severity contributions, "
            "capped at 100."
        ),
    }
