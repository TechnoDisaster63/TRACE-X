"""M13 - evidence-backed offline prevention intelligence export.

The output is TRACE-X JSON/CSV, not STIX. It performs no network or control
action. Exported records are review aids and are never safe for automated
enforcement in this prototype.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import urlsplit


class IOCExportError(ValueError):
    """IOC export input is malformed or unsupported."""


EXPORT_SCHEMA = "TRACE-X-IOC-1.0"
VALID_ACTIONS = {
    "ALLOW_WITH_NOTICE", "FLAG_FOR_REVIEW", "REQUIRE_ANALYST_REVIEW",
    "HOLD_FOR_REVIEW", "ESCALATE_TO_SOC", "REQUEST_ADDITIONAL_ANALYSIS",
}
CSV_FIELDS = [
    "indicator_id", "indicator_type", "indicator_value", "source_investigation_id",
    "evidence_id", "source_module", "confidence_label", "confidence_is_probability",
    "observed_at", "review_after", "expires_at", "recommended_action", "reason",
    "verification_status", "safe_for_automated_enforcement", "limitations",
]


def _utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise IOCExportError("observed_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IOCExportError("observed_at must be an ISO-8601 string") from exc
    if parsed.tzinfo is None:
        raise IOCExportError("observed_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def _stable_id(investigation_id: str, evidence_id: str, indicator_type: str, value: str) -> str:
    material = "|".join((investigation_id, evidence_id, indicator_type, value))
    return "IOC-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16].upper()


def _url_indicator(value: str) -> Optional[tuple]:
    if any(ord(character) < 32 or character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port  # Force validation of malformed/out-of-range ports.
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    try:
        hostname.encode("idna")
    except UnicodeError:
        return None
    return "URL", value


def _ip_indicator(text: str) -> Optional[tuple]:
    for token in text.replace("=", " ").split():
        candidate = token.strip("[](),;<>\"")
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return "IP_ADDRESS", str(ip)
    return None


def _email_or_domain_indicator(text: str) -> Optional[tuple]:
    # Identity evidence values use descriptive text. Export only exact values
    # after known labels instead of guessing from arbitrary prose.
    for label in ("From domain:", "Reply-To domain:", "Return-Path domain:"):
        if label in text:
            value = text.split(label, 1)[1].split("|", 1)[0].strip().lower()
            try:
                ascii_value = value.encode("idna").decode("ascii")
            except UnicodeError:
                continue
            labels = ascii_value.rstrip(".").split(".")
            if (
                len(labels) >= 2
                and all(label and len(label) <= 63 and label[0] != "-" and label[-1] != "-" for label in labels)
                and all(all(character.isalnum() or character == "-" for character in label) for label in labels)
            ):
                return "DOMAIN", ascii_value.rstrip(".")
    return None


def _extract_indicator(evidence: dict) -> Optional[tuple]:
    source = evidence.get("source")
    raw_value = evidence.get("evidence")
    if not isinstance(source, str) or not isinstance(raw_value, str):
        return None
    value = raw_value.strip()
    if source == "url:structural_analysis":
        return _url_indicator(value)
    if source in {"received:earliest_hop_identified", "received:private_ip_as_origin"}:
        return _ip_indicator(value)
    if source in {
        "identity:reply_to_domain_mismatch", "identity:lookalike_domain",
        "identity:homoglyph_lookalike", "identity:punycode_domain",
        "header:return_path_vs_from",
    }:
        return _email_or_domain_indicator(value)
    return None


def build_ioc_export(
    investigation: dict,
    observed_at: str,
    review_days: int = 30,
    expiration_days: int = 90,
) -> dict:
    """Build deterministic evidence-backed indicators from one investigation."""
    if not isinstance(investigation, dict):
        raise IOCExportError("investigation must be a mapping")
    investigation_id = investigation.get("investigation_id")
    if not isinstance(investigation_id, str) or not investigation_id.strip():
        raise IOCExportError("investigation_id must be a non-empty string")
    if type(review_days) is not int or type(expiration_days) is not int:
        raise IOCExportError("review and expiration days must be integers")
    if review_days < 1 or expiration_days < review_days:
        raise IOCExportError("expiration_days must be >= review_days >= 1")
    observed = _utc(observed_at)
    try:
        review_after = observed + timedelta(days=review_days)
        expires_at = observed + timedelta(days=expiration_days)
    except (OverflowError, ValueError) as exc:
        raise IOCExportError("review or expiration date is out of range") from exc

    prevention = investigation.get("prevention") or {}
    if not isinstance(prevention, dict):
        raise IOCExportError("prevention must be a mapping")
    recommended_action = prevention.get("recommended_action") or "REQUEST_ADDITIONAL_ANALYSIS"
    if recommended_action not in VALID_ACTIONS:
        raise IOCExportError("recommended_action is unsupported")

    evidence_container = investigation.get("evidence")
    if evidence_container is None:
        evidence_container = {}
    if not isinstance(evidence_container, dict):
        raise IOCExportError("evidence must be a mapping")
    evidence_items = evidence_container.get("evidence", [])
    if not isinstance(evidence_items, list):
        raise IOCExportError("evidence.evidence must be a list")

    candidates: List[dict] = []
    for evidence in evidence_items:
        if not isinstance(evidence, dict):
            raise IOCExportError("every evidence item must be a mapping")
        evidence_id = evidence.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            continue
        extracted = _extract_indicator(evidence)
        if not extracted:
            continue
        indicator_type, indicator_value = extracted
        confidence = evidence.get("confidence") if evidence.get("confidence") in {"LOW", "MEDIUM", "HIGH"} else "LOW"
        source_module = evidence.get("module") if isinstance(evidence.get("module"), str) else None
        reason = evidence.get("finding") if isinstance(evidence.get("finding"), str) and evidence.get("finding") else "Evidence-backed indicator from TRACE-X analysis."
        candidates.append({
            "indicator_id": _stable_id(investigation_id, evidence_id, indicator_type, indicator_value),
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "source_investigation_id": investigation_id,
            "evidence_id": evidence_id,
            "source_module": source_module,
            "confidence_label": confidence,
            "confidence_is_probability": False,
            "observed_at": observed.isoformat(),
            "review_after": review_after.isoformat(),
            "expires_at": expires_at.isoformat(),
            "recommended_action": recommended_action,
            "reason": reason,
            "verification_status": "HEURISTIC_OR_REPORTED",
            "safe_for_automated_enforcement": False,
            "limitations": (
                "Review aid only. The indicator is derived from offline analysis; "
                "no live reputation or ownership check was performed."
            ),
        })
    # Sort before deduplication so input order cannot decide provenance. For
    # repeated observables, the lexicographically first evidence ID is retained.
    candidates.sort(key=lambda item: (item["indicator_type"], item["indicator_value"], item["evidence_id"]))
    records: List[dict] = []
    seen = set()
    for candidate in candidates:
        key = (candidate["indicator_type"], candidate["indicator_value"])
        if key not in seen:
            records.append(candidate)
            seen.add(key)
    return {
        "schema": EXPORT_SCHEMA,
        "format_note": "TRACE-X JSON/CSV; not STIX",
        "source_investigation_id": investigation_id,
        "generated_from_observation_time": observed.isoformat(),
        "indicator_count": len(records),
        "indicators": records,
        "execution": {
            "mode": "OFFLINE_EXPORT_ONLY",
            "network_calls": False,
            "external_actions": False,
            "automated_enforcement_allowed": False,
        },
        "limitations": [
            "Confidence labels are ordinal review labels, not probabilities.",
            "Weak or ambiguous evidence is not promoted to confirmed malicious status.",
            "No SIEM, firewall, gateway, mailbox, reputation, or network action is performed.",
        ],
    }


def _validate_export_invariants(export: dict) -> None:
    if not isinstance(export, dict):
        raise IOCExportError("export must be a mapping")
    execution = export.get("execution")
    if execution is not None and (
        not isinstance(execution, dict)
        or execution.get("network_calls") is not False
        or execution.get("external_actions") is not False
        or execution.get("automated_enforcement_allowed") is not False
    ):
        raise IOCExportError("offline execution invariants must remain false")
    indicators = export.get("indicators", [])
    if not isinstance(indicators, list):
        raise IOCExportError("indicators must be a list")
    for item in indicators:
        if not isinstance(item, dict):
            raise IOCExportError("every indicator must be a mapping")
        if item.get("safe_for_automated_enforcement") is not False:
            raise IOCExportError("automated enforcement must remain false")
        if item.get("confidence_is_probability") is not False:
            raise IOCExportError("confidence must remain non-probabilistic")


def to_json(export: dict) -> str:
    _validate_export_invariants(export)
    # No default=str: unsupported objects must fail rather than be silently
    # converted into misleading export data.
    return json.dumps(export, indent=2, sort_keys=True)


def _csv_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    # Quoting is not enough for spreadsheet formula injection. Prefix cells
    # whose first non-space character can trigger a formula in common viewers.
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def to_csv(export: dict) -> str:
    _validate_export_invariants(export)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for item in export.get("indicators", []):
        if not isinstance(item, dict):
            raise IOCExportError("every indicator must be a mapping")
        row = {field: _csv_safe(item.get(field, "")) for field in CSV_FIELDS}
        # These are hard exporter invariants, not caller-controlled fields.
        row["confidence_is_probability"] = "false"
        row["safe_for_automated_enforcement"] = "false"
        writer.writerow(row)
    return output.getvalue()
