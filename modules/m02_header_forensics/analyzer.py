"""
M02 — Header Forensics

Consumes ParsedEmail (M01 output) and produces structured forensic
findings about header anomalies, mismatches, and suspicious patterns.
Makes NO conclusions about maliciousness -- only observations tied to evidence.
"""
import re
from email.utils import parsedate_to_datetime, getaddresses
from typing import List

from core.models import Finding, findings_summary, ParsedEmail

_counter = {"n": 0}


def _next_id() -> str:
    _counter["n"] += 1
    return f"HDR-{_counter['n']:03d}"


def _domain_of(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower().strip(">")


def reset_counter():
    _counter["n"] = 0


def analyze_headers(parsed: ParsedEmail) -> dict:
    reset_counter()
    findings: List[Finding] = []

    from_addr = parsed.from_ or ""
    reply_to = parsed.reply_to or ""
    return_path = parsed.return_path or ""
    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to)
    return_domain = _domain_of(return_path)

    # --- Reply-To mismatch ---
    if reply_to and from_addr and reply_domain and from_domain and reply_domain != from_domain:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Reply-To address differs from From address",
            severity="HIGH",
            evidence=f"From: {from_addr} | Reply-To: {reply_to}",
            source="header:reply_to_vs_from",
            confidence="HIGH",
            category="MISMATCH",
        ))

    # --- Return-Path mismatch ---
    if return_path and from_addr and return_domain and from_domain and return_domain != from_domain:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Return-Path domain differs from From domain",
            severity="MEDIUM",
            evidence=f"From: {from_addr} | Return-Path: {return_path}",
            source="header:return_path_vs_from",
            confidence="MEDIUM",
            category="MISMATCH",
        ))

    # --- Missing Message-ID ---
    if not parsed.message_id:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Missing Message-ID header",
            severity="MEDIUM",
            evidence="No Message-ID header present in email",
            source="header:message_id_missing",
            confidence="HIGH",
            category="MISSING",
        ))
    else:
        # --- Message-ID domain anomaly (domain unrelated to From domain) ---
        m = re.search(r"@([A-Za-z0-9.\-]+)>?$", parsed.message_id.strip())
        if m and from_domain:
            msgid_domain = m.group(1).lower()
            if msgid_domain != from_domain and not msgid_domain.endswith("." + from_domain):
                findings.append(Finding(
                    finding_id=_next_id(),
                    finding="Message-ID domain does not match From domain",
                    severity="LOW",
                    evidence=f"Message-ID domain: {msgid_domain} | From domain: {from_domain}",
                    source="header:message_id_domain_anomaly",
                    confidence="LOW",
                    category="ANOMALY",
                ))

    # --- Missing From ---
    if not parsed.from_:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Missing or unparsable From header",
            severity="HIGH",
            evidence="No usable From address found",
            source="header:from_missing",
            confidence="HIGH",
            category="MISSING",
        ))

    # --- Missing Date / unparsable Date ---
    if not parsed.date:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Missing Date header",
            severity="LOW",
            evidence="No Date header present",
            source="header:date_missing",
            confidence="HIGH",
            category="MISSING",
        ))
    else:
        try:
            parsedate_to_datetime(parsed.date)
        except Exception:
            findings.append(Finding(
                finding_id=_next_id(),
                finding="Date header is malformed / unparsable",
                severity="LOW",
                evidence=f"Date: {parsed.date}",
                source="header:date_malformed",
                confidence="MEDIUM",
                category="ANOMALY",
            ))

    # --- Missing Received headers (direct injection indicator) ---
    if not parsed.received:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="No Received headers present (unusual for delivered mail)",
            severity="MEDIUM",
            evidence="Zero Received headers found",
            source="header:received_missing",
            confidence="MEDIUM",
            category="MISSING",
        ))

    # --- Duplicate / conflicting Authentication-Results headers ---
    auth_header_keys = [k for k in parsed.raw_headers.keys()
                         if k.lower() in ("authentication-results", "x-authentication-results")]
    if any(k.lower() == "x-authentication-results" for k in auth_header_keys):
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Non-standard X-Authentication-Results header present",
            severity="MEDIUM",
            evidence="An X-Authentication-Results header was found alongside/instead of the standard header; "
                      "this is a known technique to spoof trust indicators since it is not verified by receiving MTAs",
            source="header:nonstandard_auth_header",
            confidence="MEDIUM",
            category="SUSPICIOUS_STRUCTURE",
        ))

    # --- Display-name / From header structural anomaly (multiple @ or angle brackets in raw) ---
    raw_from_values = parsed.raw_headers.get("From", [])
    for raw_val in raw_from_values:
        if raw_val.count("@") > 1:
            findings.append(Finding(
                finding_id=_next_id(),
                finding="From header contains multiple '@' symbols (possible header injection attempt)",
                severity="HIGH",
                evidence=f"Raw From header: {raw_val}",
                source="header:from_multiple_at",
                confidence="MEDIUM",
                category="SUSPICIOUS_STRUCTURE",
            ))

    summary = findings_summary(findings)
    return {
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
        "analyzed_headers": {
            "from": from_addr,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": parsed.message_id,
            "date": parsed.date,
            "received_count": len(parsed.received),
        },
    }
