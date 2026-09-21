"""
M03 — SPF/DKIM/DMARC Analyzer

Parses Authentication-Results headers from M01 output into structured,
nuanced findings. Authentication results are signals, not verdicts:
a PASS does not mean safe, a FAIL does not mean malicious.
"""
import re
from typing import Dict, List, Optional

from core.models import Finding, findings_summary, ParsedEmail

_counter = {"n": 0}


def reset_counter():
    _counter["n"] = 0


def _next_id() -> str:
    _counter["n"] += 1
    return f"AUTH-{_counter['n']:03d}"


VALID_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "unknown", "policy", "temperror", "permerror"}


def _parse_mechanism(auth_header: str, mechanism: str) -> Dict[str, Optional[str]]:
    """Extract result + domain for a given mechanism (spf/dkim/dmarc) from a raw
    Authentication-Results header string."""
    pattern = re.compile(
        rf"{mechanism}=([a-zA-Z]+)([^;]*)", re.IGNORECASE
    )
    m = pattern.search(auth_header)
    if not m:
        return {"result": "none", "domain": None, "raw": None, "selector": None}

    result = m.group(1).lower()
    if result not in VALID_RESULTS:
        result = "unknown"
    tail = m.group(2)

    domain = None
    domain_match = re.search(
        r"(?:smtp\.mailfrom|header\.d|header\.from)=([A-Za-z0-9.\-]+)", tail, re.IGNORECASE
    )
    if domain_match:
        domain = domain_match.group(1).lower()

    selector = None
    if mechanism == "dkim":
        sel_match = re.search(r"header\.s=([A-Za-z0-9.\-]+)", tail, re.IGNORECASE)
        if sel_match:
            selector = sel_match.group(1)

    raw_full = m.group(0).strip()
    return {"result": result, "domain": domain, "raw": raw_full, "selector": selector}


def _dmarc_policy(auth_header: str) -> Optional[str]:
    m = re.search(r"dmarc=[a-zA-Z]+[^;]*\bpolicy=([a-zA-Z]+)", auth_header, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    m2 = re.search(r"\bp=([a-zA-Z]+)", auth_header, re.IGNORECASE)
    if m2:
        return m2.group(1).lower()
    return None


INTERPRETATIONS = {
    ("spf", "pass"): "The selected Authentication-Results header reports SPF=pass. TRACE-X did not query DNS or independently verify the sending IP. This does not confirm the message is safe.",
    ("spf", "fail"): "The selected Authentication-Results header reports SPF=fail. Treat this as a reported signal and review it with other evidence.",
    ("spf", "softfail"): "The selected Authentication-Results header reports SPF=softfail. Treat this as a reported signal and review it with other evidence.",
    ("spf", "neutral"): "The selected Authentication-Results header reports SPF=neutral; TRACE-X did not independently evaluate the domain policy.",
    ("spf", "none"): "No SPF result was found in the selected reported headers.",
    ("dkim", "pass"): "The selected Authentication-Results header reports DKIM=pass. TRACE-X did not verify the signature or retrieve the public key, and the reported pass does not confirm the message is safe.",
    ("dkim", "fail"): "The selected Authentication-Results header reports DKIM=fail. TRACE-X did not independently reproduce the validation.",
    ("dkim", "none"): "No DKIM result was found in the selected reported headers.",
    ("dmarc", "pass"): "The selected Authentication-Results header reports DMARC=pass. TRACE-X did not independently evaluate SPF/DKIM or retrieve the DMARC policy.",
    ("dmarc", "fail"): "The selected Authentication-Results header reports DMARC=fail. Treat this as a reported signal and review it with other evidence.",
    ("dmarc", "none"): "No DMARC result was found in the selected reported headers.",
}


def _interpret(mechanism: str, result: str) -> str:
    return INTERPRETATIONS.get((mechanism, result),
                                f"{mechanism.upper()} result '{result}': no additional interpretation available.")


def _authserv_id(auth_header: str) -> Optional[str]:
    """Return the Authentication-Results authserv-id before the first semicolon.

    This is provenance metadata only. Identity is not inferred from the header;
    callers must explicitly configure trusted receiver identifiers.
    """
    if not auth_header or ";" not in auth_header:
        return None
    candidate = auth_header.split(";", 1)[0].strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", candidate):
        return None
    return candidate


def analyze_authentication(
    parsed: ParsedEmail,
    trusted_authserv_ids: Optional[List[str]] = None,
) -> dict:
    reset_counter()
    findings: List[Finding] = []
    warnings: List[str] = []
    spf_aligned = None
    dkim_aligned = None

    trusted_ids = {
        value.strip().lower().rstrip(".")
        for value in (trusted_authserv_ids or [])
        if value and value.strip()
    }
    auth_headers = list(parsed.authentication_results)
    combined = " ; ".join(auth_headers)

    def _select_mechanism(mechanism: str) -> Dict:
        """Deterministic selection policy: each Authentication-Results header is
        parsed INDEPENDENTLY, and the first header (in received order) that
        contains this mechanism supplies its result. Raw Authentication-Results
        order is newest-first, so this prefers the most recently added header,
        i.e. the hop closest to the analyzer. Values are never mixed across
        headers, and provenance (header_index / header_value) is attached."""
        for idx, hdr in enumerate(auth_headers):
            r = _parse_mechanism(hdr, mechanism)
            if r.get("raw") is not None:
                r = dict(r)
                r["header_index"] = idx
                r["header_value"] = hdr
                r["authserv_id"] = _authserv_id(hdr)
                r["trusted_source"] = r["authserv_id"] in trusted_ids
                return r
        return {"result": "none", "domain": None, "selector": None, "raw": None,
                "header_index": None, "header_value": None, "authserv_id": None,
                "trusted_source": False}

    if not auth_headers:
        warnings.append("No Authentication-Results header present")
        spf = {"result": "none", "domain": None, "raw": None, "header_index": None,
               "header_value": None, "authserv_id": None, "trusted_source": False,
               "interpretation": _interpret("spf", "none")}
        dkim = {"result": "none", "domain": None, "selector": None, "raw": None, "header_index": None,
                "header_value": None, "authserv_id": None, "trusted_source": False,
                "interpretation": _interpret("dkim", "none")}
        dmarc = {"result": "none", "policy": None, "raw": None, "header_index": None,
                 "header_value": None, "authserv_id": None, "trusted_source": False,
                 "interpretation": _interpret("dmarc", "none")}
        findings.append(Finding(
            finding_id=_next_id(),
            finding="No Authentication-Results header found",
            severity="MEDIUM",
            evidence="Email lacks any Authentication-Results header",
            source="auth:missing_header",
            confidence="MEDIUM",
            category="MISSING",
        ))
    else:
        spf_r = _select_mechanism("spf")
        dkim_r = _select_mechanism("dkim")
        dmarc_r = _select_mechanism("dmarc")
        # DMARC policy must come from the SAME header that supplied the DMARC
        # result -- never from any other (or merged) header.
        dmarc_policy = _dmarc_policy(dmarc_r["header_value"]) if dmarc_r.get("header_value") else None

        spf = {"result": spf_r["result"], "domain": spf_r["domain"], "raw": spf_r["raw"],
               "header_index": spf_r["header_index"], "header_value": spf_r["header_value"],
               "authserv_id": spf_r["authserv_id"], "trusted_source": spf_r["trusted_source"],
               "interpretation": _interpret("spf", spf_r["result"])}
        dkim = {"result": dkim_r["result"], "domain": dkim_r["domain"], "selector": dkim_r["selector"],
                "raw": dkim_r["raw"], "header_index": dkim_r["header_index"],
                "header_value": dkim_r["header_value"], "authserv_id": dkim_r["authserv_id"],
                "trusted_source": dkim_r["trusted_source"],
                "interpretation": _interpret("dkim", dkim_r["result"])}
        dmarc = {"result": dmarc_r["result"], "policy": dmarc_policy, "raw": dmarc_r["raw"],
                 "header_index": dmarc_r["header_index"], "header_value": dmarc_r["header_value"],
                 "authserv_id": dmarc_r["authserv_id"], "trusted_source": dmarc_r["trusted_source"],
                 "interpretation": _interpret("dmarc", dmarc_r["result"])}

        # --- Findings for failing/weak mechanisms ---
        if spf["result"] in ("fail", "softfail"):
            findings.append(Finding(
                finding_id=_next_id(),
                finding=f"SPF result: {spf['result']}",
                severity="HIGH" if spf["result"] == "fail" else "MEDIUM",
                evidence=spf["raw"] or "spf result reported as " + spf["result"],
                source="auth:spf_fail",
                confidence="MEDIUM",
                category="AUTHENTICATION",
            ))
        if dkim["result"] in ("fail", "none"):
            findings.append(Finding(
                finding_id=_next_id(),
                finding=f"DKIM result: {dkim['result']}",
                severity="MEDIUM",
                evidence=dkim["raw"] or "dkim result reported as " + dkim["result"],
                source="auth:dkim_weak",
                confidence="MEDIUM",
                category="AUTHENTICATION",
            ))
        if dmarc["result"] in ("fail", "none"):
            findings.append(Finding(
                finding_id=_next_id(),
                finding=f"DMARC result: {dmarc['result']}",
                severity="HIGH" if dmarc["result"] == "fail" else "MEDIUM",
                evidence=dmarc["raw"] or "dmarc result reported as " + dmarc["result"],
                source="auth:dmarc_weak",
                confidence="MEDIUM",
                category="AUTHENTICATION",
            ))

        # --- Manipulation detection: comments injected inside the auth value ---
        if re.search(r"spf=pass\s*\([^)]*\)", combined, re.IGNORECASE) and \
           re.search(r"\((?:forged|injected|fake|spoofed)", combined, re.IGNORECASE):
            findings.append(Finding(
                finding_id=_next_id(),
                finding="Authentication-Results header contains suspicious inline commentary suggesting manipulation",
                severity="HIGH",
                evidence=combined[:200],
                source="auth:header_manipulation_suspected",
                confidence="LOW",
                category="SUSPICIOUS_STRUCTURE",
            ))

        # --- Alignment check (best-effort, no DNS lookups) ---
        from_domain = (parsed.from_ or "").rsplit("@", 1)[-1].lower() if parsed.from_ and "@" in parsed.from_ else None
        spf_aligned = None
        dkim_aligned = None
        if from_domain and spf["domain"]:
            spf_aligned = spf["domain"] == from_domain
        if from_domain and dkim["domain"]:
            dkim_aligned = dkim["domain"] == from_domain

        if spf_aligned is False or dkim_aligned is False:
            findings.append(Finding(
                finding_id=_next_id(),
                finding="Authenticated domain does not align with visible From domain",
                severity="MEDIUM",
                evidence=f"From domain: {from_domain} | SPF domain: {spf['domain']} | DKIM domain: {dkim['domain']}",
                source="auth:alignment_mismatch",
                confidence="MEDIUM",
                category="MISMATCH",
            ))

    summary = findings_summary(findings)
    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "provenance": {
            "mode": "TRUSTED_AUTHserv_ID_ALLOWLIST" if trusted_ids else "REPORTED_UNVERIFIED",
            "trusted_authserv_ids": sorted(trusted_ids),
            "warning": (
                "Authentication results are reported by message headers and were not "
                "independently verified. Only results whose authserv-id matches the "
                "explicit allowlist are marked trusted_source=true."
            ),
        },
        "alignment": {
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "analysis": "Alignment computed by string comparison only; no DNS validation performed.",
        },
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
        "warnings": warnings,
    }
