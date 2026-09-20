"""
M07 — Evidence Engine

Standardization layer. Takes findings from M02-M06 (each already emits
Finding-shaped dicts, but from independent ID sequences) and merges them
into a single, deduplicated, uniquely-IDed EvidenceBundle that downstream
modules (Risk Engine, Threat Graph, Report Generator) consume consistently.

No finding is dropped silently. No finding is invented.
"""
from typing import Dict, List

from core.models import findings_summary, Finding
from core.utils import severity_rank

_counter = {"n": 0}


def reset_counter():
    _counter["n"] = 0


def _next_evidence_id() -> str:
    _counter["n"] += 1
    return f"EVID-{_counter['n']:04d}"


MODULE_SOURCE_LABEL = {
    "header_forensics": "M02_HEADER_FORENSICS",
    "authentication": "M03_AUTH_ANALYZER",
    "identity": "M04_IDENTITY_ANALYZER",
    "received_chain": "M05_RECEIVED_CHAIN",
    "url_analysis": "M06_URL_ANALYZER",
}


def build_evidence_bundle(
    header_result: dict,
    auth_result: dict,
    identity_result: dict,
    received_result: dict,
    url_result: dict,
) -> dict:
    """Merge findings from M02-M06 into one normalized, evidence-tied bundle."""
    reset_counter()
    evidence_items: List[Dict] = []

    module_results = {
        "header_forensics": header_result,
        "authentication": auth_result,
        "identity": identity_result,
        "received_chain": received_result,
        "url_analysis": url_result,
    }

    seen_dedup_keys = set()

    for module_key, result in module_results.items():
        module_label = MODULE_SOURCE_LABEL[module_key]
        for raw_finding in result.get("findings", []):
            # Dedup identical (finding text + evidence) pairs across modules
            dedup_key = (raw_finding["finding"], raw_finding["evidence"])
            if dedup_key in seen_dedup_keys:
                continue
            seen_dedup_keys.add(dedup_key)

            evidence_items.append({
                "evidence_id": _next_evidence_id(),
                "finding": raw_finding["finding"],
                "severity": raw_finding["severity"],
                "evidence": raw_finding["evidence"],
                "source": raw_finding["source"],
                "confidence": raw_finding["confidence"],
                "category": raw_finding.get("category", "GENERAL"),
                "module": module_label,
                "original_finding_id": raw_finding["finding_id"],
            })

    # Sort by severity (highest first) for readability; ties keep insertion order
    evidence_items.sort(key=lambda e: severity_rank(e["severity"]), reverse=True)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for e in evidence_items:
        severity_counts[e["severity"].lower()] += 1

    by_module_counts = {}
    for e in evidence_items:
        by_module_counts[e["module"]] = by_module_counts.get(e["module"], 0) + 1

    return {
        "evidence": evidence_items,
        "total_evidence_count": len(evidence_items),
        "severity_counts": severity_counts,
        "by_module_counts": by_module_counts,
        "module_summaries": {
            module_key: result.get("summary", {})
            for module_key, result in module_results.items()
        },
    }
