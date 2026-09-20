"""
M04 — Identity Analyzer

Analyzes who the email claims to be from (display name) vs. who it
actually appears to be from (From/Reply-To/Return-Path addresses).
Detects display-name impersonation, domain mismatch, look-alike domains,
typosquatting, and punycode/IDN indicators.

Does NOT assume a legitimate organization domain automatically -- trusted
domain context must be explicitly supplied by the caller.
"""
import re
from email.utils import parseaddr
from typing import List, Optional

from core.models import Finding, findings_summary, ParsedEmail

_counter = {"n": 0}


def reset_counter():
    _counter["n"] = 0


def _next_id() -> str:
    _counter["n"] += 1
    return f"ID-{_counter['n']:03d}"


# Common brand names commonly impersonated in display names (illustrative,
# non-exhaustive; extend via trusted_domains/known_brands parameter)
KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "bank of america": ["bankofamerica.com"],
    "docusign": ["docusign.com", "docusign.net"],
}

# Characters commonly used to visually impersonate ASCII letters
HOMOGLYPH_DIGIT_SUBS = {"0": "o", "1": "l", "1": "i", "5": "s", "3": "e", "@": "a"}


def _domain_of(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower().strip(">")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def _normalize_homoglyphs(domain: str) -> str:
    out = domain
    subs = {"0": "o", "1": "l", "5": "s", "3": "e", "@": "a", "vv": "w"}
    for k, v in subs.items():
        out = out.replace(k, v)
    return out


def _is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def _detect_brand_impersonation(display_name: str, from_domain: str, known_brands: dict) -> Optional[str]:
    dn = (display_name or "").lower()
    for brand, legit_domains in known_brands.items():
        if brand in dn:
            if not any(from_domain == d or from_domain.endswith("." + d) for d in legit_domains):
                return brand
    return None


def _typosquat_candidates(from_domain: str, trusted_domains: List[str]) -> Optional[str]:
    if not from_domain:
        return None
    norm_from = _normalize_homoglyphs(from_domain)
    for trusted in trusted_domains:
        norm_trusted = _normalize_homoglyphs(trusted.lower())
        if from_domain == trusted:
            continue
        dist = _levenshtein(norm_from, norm_trusted)
        if 0 < dist <= 2 and abs(len(norm_from) - len(norm_trusted)) <= 2:
            return trusted
    return None


def analyze_identity(parsed: ParsedEmail, trusted_domains: Optional[List[str]] = None,
                      known_brands: Optional[dict] = None) -> dict:
    reset_counter()
    findings: List[Finding] = []
    trusted_domains = trusted_domains or []
    known_brands = known_brands or KNOWN_BRANDS

    raw_from_values = parsed.raw_headers.get("From", [])
    display_name = ""
    if raw_from_values:
        display_name, _ = parseaddr(raw_from_values[0])

    from_addr = parsed.from_ or ""
    reply_to = parsed.reply_to or ""
    return_path = parsed.return_path or ""
    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to)
    return_path_domain = _domain_of(return_path)

    # --- Display-name brand impersonation ---
    brand_hit = _detect_brand_impersonation(display_name, from_domain, known_brands)
    if brand_hit:
        findings.append(Finding(
            finding_id=_next_id(),
            finding=f"Display name references brand '{brand_hit}' but From domain does not match that brand's known domains",
            severity="HIGH",
            evidence=f"Display name: '{display_name}' | From domain: {from_domain}",
            source="identity:display_name_brand_impersonation",
            confidence="MEDIUM",
            category="IMPERSONATION",
        ))

    # --- Punycode / IDN indicator ---
    if from_domain and _is_punycode(from_domain):
        findings.append(Finding(
            finding_id=_next_id(),
            finding="From domain uses punycode/IDN encoding (possible homograph attack)",
            severity="HIGH",
            evidence=f"From domain: {from_domain}",
            source="identity:punycode_domain",
            confidence="MEDIUM",
            category="IMPERSONATION",
        ))

    # --- Look-alike / typosquat detection against explicitly trusted domains ---
    if trusted_domains:
        candidate = _typosquat_candidates(from_domain, trusted_domains)
        if candidate:
            findings.append(Finding(
                finding_id=_next_id(),
                finding=f"From domain closely resembles trusted domain '{candidate}' (possible typosquat/look-alike)",
                severity="HIGH",
                evidence=f"From domain: {from_domain} | Similar to trusted domain: {candidate}",
                source="identity:lookalike_domain",
                confidence="MEDIUM",
                category="IMPERSONATION",
            ))

    # --- Heuristic look-alike detection for common character substitutions
    #     even without explicit trusted-domain context, restricted to a small,
    #     documented set of very common brand-domain look-alikes. ---
    _heuristic_brand_domains = {
        "paypal.com", "microsoft.com", "apple.com", "google.com", "amazon.com",
    }
    if from_domain:
        norm_from = _normalize_homoglyphs(from_domain)
        for legit in _heuristic_brand_domains:
            if from_domain != legit and norm_from == legit:
                findings.append(Finding(
                    finding_id=_next_id(),
                    finding=f"From domain '{from_domain}' visually resembles well-known domain '{legit}' via character substitution",
                    severity="CRITICAL",
                    evidence=f"From domain: {from_domain} normalizes to '{norm_from}', matching '{legit}'",
                    source="identity:homoglyph_lookalike",
                    confidence="HIGH",
                    category="IMPERSONATION",
                ))

    # --- Display name shows a different address than the actual From ---
    if display_name and "@" in display_name:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Display name itself contains an email address, potentially masking the real sender",
            severity="MEDIUM",
            evidence=f"Display name: '{display_name}'",
            source="identity:display_name_contains_address",
            confidence="LOW",
            category="SUSPICIOUS_STRUCTURE",
        ))

    # --- Reply-To domain differs from From domain (identity-level, complements M02) ---
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="Reply-To domain differs from From domain (identity mismatch)",
            severity="MEDIUM",
            evidence=f"From domain: {from_domain} | Reply-To domain: {reply_domain}",
            source="identity:reply_to_domain_mismatch",
            confidence="MEDIUM",
            category="MISMATCH",
        ))

    summary = findings_summary(findings)
    return {
        "display_name": display_name,
        "from_address": from_addr,
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_path_domain,
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
    }
