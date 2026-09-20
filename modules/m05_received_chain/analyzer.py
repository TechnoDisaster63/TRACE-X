"""
M05 — Received-Chain Analyzer

Parses Received headers into an ordered hop chain (oldest first).
Classifies each extracted fact as OBSERVED, INFERRED, or UNCERTAIN.
Never labels an IP as "attacker IP" -- uses "earliest observable
infrastructure" instead.
"""
import re
from typing import Dict, List, Optional

from core.models import Finding, findings_summary, ParsedEmail

_counter = {"n": 0}


def reset_counter():
    _counter["n"] = 0


def _next_id() -> str:
    _counter["n"] += 1
    return f"RCV-{_counter['n']:03d}"


IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})\b")
HOSTNAME_RE = re.compile(r"from\s+([A-Za-z0-9.\-]+)", re.IGNORECASE)
BY_RE = re.compile(r"\bby\s+([A-Za-z0-9.\-]+)", re.IGNORECASE)
TIMESTAMP_RE = re.compile(r";\s*(.+)$")

PRIVATE_IP_RE = re.compile(
    r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)"
)


def _is_private_ip(ip: str) -> bool:
    return bool(PRIVATE_IP_RE.match(ip))


def _parse_one_received(header: str) -> Dict:
    hostname_match = HOSTNAME_RE.search(header)
    by_match = BY_RE.search(header)
    ipv4_matches = IPV4_RE.findall(header)
    ipv6_matches = IPV6_RE.findall(header)
    ts_match = TIMESTAMP_RE.search(header)

    hostname = hostname_match.group(1) if hostname_match else None
    by_host = by_match.group(1) if by_match else None
    ip = ipv4_matches[0] if ipv4_matches else (ipv6_matches[0] if ipv6_matches else None)
    timestamp = ts_match.group(1).strip() if ts_match else None

    # Classification of confidence in the extracted facts
    if hostname and ip:
        classification = "OBSERVED"
    elif hostname or ip:
        classification = "INFERRED"
    else:
        classification = "UNCERTAIN"

    return {
        "raw": header.strip(),
        "hostname": hostname,
        "by": by_host,
        "ip": ip,
        "timestamp": timestamp,
        "is_private_ip": _is_private_ip(ip) if ip else None,
        "classification": classification,
    }


def analyze_received_chain(parsed: ParsedEmail) -> dict:
    reset_counter()
    findings: List[Finding] = []

    raw_hops = parsed.received or []
    # Received headers appear newest-first in raw email; reverse to get
    # oldest-first (origin -> destination) chronological order.
    ordered_raw = list(reversed(raw_hops))
    hops = [_parse_one_received(h) for h in ordered_raw]

    for i, hop in enumerate(hops, start=1):
        hop["hop_number"] = i

    if not hops:
        findings.append(Finding(
            finding_id=_next_id(),
            finding="No Received headers available to reconstruct mail path",
            severity="MEDIUM",
            evidence="Zero Received headers present",
            source="received:no_hops",
            confidence="MEDIUM",
            category="MISSING",
        ))
    else:
        earliest = hops[0]
        if earliest["classification"] == "UNCERTAIN":
            findings.append(Finding(
                finding_id=_next_id(),
                finding="Earliest observable infrastructure could not be reliably identified",
                severity="LOW",
                evidence=f"Raw header: {earliest['raw'][:200]}",
                source="received:earliest_hop_uncertain",
                confidence="LOW",
                category="ANOMALY",
            ))
        else:
            findings.append(Finding(
                finding_id=_next_id(),
                finding="Earliest observable infrastructure identified in mail path",
                severity="INFO",
                evidence=f"host={earliest['hostname']} ip={earliest['ip']}",
                source="received:earliest_hop_identified",
                confidence="MEDIUM" if earliest["classification"] == "INFERRED" else "HIGH",
                category="INFO",
            ))

        # Suspicious: a private/internal IP appearing as the *earliest* external hop
        if earliest.get("ip") and earliest.get("is_private_ip"):
            findings.append(Finding(
                finding_id=_next_id(),
                finding="Earliest hop reports a private/internal IP address, which is unusual for external mail origin",
                severity="LOW",
                evidence=f"IP: {earliest['ip']}",
                source="received:private_ip_as_origin",
                confidence="LOW",
                category="ANOMALY",
            ))

        # Excessive hop count (possible relay abuse / loops), documented threshold
        if len(hops) > 15:
            findings.append(Finding(
                finding_id=_next_id(),
                finding=f"Unusually high number of mail hops ({len(hops)})",
                severity="LOW",
                evidence=f"Hop count: {len(hops)}",
                source="received:excessive_hops",
                confidence="LOW",
                category="ANOMALY",
            ))

    summary = findings_summary(findings)
    return {
        "hop_count": len(hops),
        "chain": hops,
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
    }
