"""
M06 — URL Analyzer

Static analysis only. URLs are never visited/fetched. Examines structural
and pattern signals: scheme, domain, subdomain count, length, IP-based
host, punycode, encoding, shortener usage, suspicious keywords, path,
and query parameters.
"""
import re
from typing import Dict, List
from urllib.parse import urlparse, parse_qs

from core.config import KNOWN_SHORTENERS, SUSPICIOUS_URL_KEYWORDS
from core.models import Finding, findings_summary, ParsedEmail

_counter = {"n": 0}


def reset_counter():
    _counter["n"] = 0


def _next_id() -> str:
    _counter["n"] += 1
    return f"URL-{_counter['n']:03d}"


IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _analyze_single_url(url: str) -> Dict:
    signals: List[str] = []
    severity = "LOW"
    confidence = "MEDIUM"

    normalized = url
    if not re.match(r"^https?://", normalized, re.IGNORECASE):
        normalized = "http://" + normalized  # for parsing only; scheme not asserted as real

    try:
        parsed = urlparse(normalized)
    except Exception:
        return {
            "url": url, "signals": ["Unparsable URL structure"], "severity": "MEDIUM",
            "evidence": url, "confidence": "LOW",
        }

    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    if scheme == "http":
        signals.append("Uses insecure HTTP scheme")

    if IP_HOST_RE.match(host):
        signals.append("Host is a raw IP address rather than a domain name")
        severity = "HIGH"

    if any(label.startswith("xn--") for label in host.split(".")):
        signals.append("Host uses punycode/IDN encoding")
        severity = "HIGH"

    subdomain_count = max(0, host.count(".") - 1)
    if subdomain_count >= 3:
        signals.append(f"Excessive subdomain count ({subdomain_count})")
        severity = max(severity, "MEDIUM", key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[s])

    if len(url) > 120:
        signals.append(f"Unusually long URL ({len(url)} characters)")

    if any(host == shortener or host.endswith("." + shortener) for shortener in KNOWN_SHORTENERS):
        signals.append("URL uses a known link-shortening service (destination is obscured)")
        severity = "MEDIUM"

    if "%" in path or "%" in query:
        signals.append("URL contains percent-encoded characters")

    lowered_full = url.lower()
    hit_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in lowered_full]
    if hit_keywords:
        signals.append(f"Contains suspicious keyword(s): {', '.join(sorted(hit_keywords))}")
        severity = "MEDIUM" if severity == "LOW" else severity

    # Domain embedded inside path/subdomain of a different host (brand-in-path spoofing)
    known_brand_domains = ["paypal.com", "microsoft.com", "apple.com", "google.com", "amazon.com", "bankofamerica.com"]
    normalized_host = host.replace("0", "o").replace("1", "l").replace("5", "s").replace("3", "e")
    for brand_domain in known_brand_domains:
        brand_name = brand_domain.split(".")[0]
        if (brand_name in host or brand_name in normalized_host) and not host.endswith(brand_domain) and host != brand_domain:
            signals.append(f"Host contains brand name '{brand_name}' but is not the legitimate '{brand_domain}' domain")
            severity = "CRITICAL"

    try:
        qs = parse_qs(query)
        if len(qs) > 6:
            signals.append(f"Unusually high number of query parameters ({len(qs)})")
    except Exception:
        signals.append("Query string could not be parsed")

    if not signals:
        signals.append("No structural anomalies detected")
        severity = "LOW"
        confidence = "LOW"

    return {
        "url": url,
        "host": host,
        "signals": signals,
        "severity": severity,
        "evidence": url,
        "confidence": confidence,
    }


def analyze_urls(parsed: ParsedEmail) -> dict:
    reset_counter()
    findings: List[Finding] = []
    url_results = []

    for url in parsed.urls:
        result = _analyze_single_url(url)
        url_results.append(result)
        if result["severity"] in ("HIGH", "CRITICAL") or (
            result["severity"] == "MEDIUM" and len(result["signals"]) >= 2
        ):
            findings.append(Finding(
                finding_id=_next_id(),
                finding=f"Suspicious URL structure detected: {'; '.join(result['signals'][:2])}",
                severity=result["severity"],
                evidence=result["url"],
                source="url:structural_analysis",
                confidence=result["confidence"],
                category="SUSPICIOUS_URL",
            ))

    if not parsed.urls:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="No URLs found in email body",
            severity="INFO",
            evidence="Zero URLs extracted",
            source="url:no_urls",
            confidence="HIGH",
            category="INFO",
        ))

    summary = findings_summary(findings)
    return {
        "url_count": len(parsed.urls),
        "urls": url_results,
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
    }
