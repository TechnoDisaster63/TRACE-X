"""M17 - offline, evidence-first IP country intelligence.

Uses only a local DB-IP Lite Country MMDB. A country describes probable mail
infrastructure location, never a person or threat actor. This database has no
ASN, ownership, WHOIS, or live-reputation fields, so those remain unavailable.
"""
from __future__ import annotations
import ipaddress
from pathlib import Path
from typing import Optional

MODULE = "M17_GEO_INFRA_INTEL"
DB_VERSION = "DB-IP Lite Country 2026-09"
DB_SOURCE = "DB-IP.com free IP-to-Country Lite, CC BY 4.0"
DEFAULT_DB_PATH = Path(__file__).with_name("data") / "dbip-country-lite-2026-09.mmdb"


def _finding(n, finding, severity, evidence, source, confidence, category="INFO"):
    return {"finding_id": f"GEO-{n:03d}", "finding": finding, "severity": severity,
            "evidence": evidence, "source": source, "confidence": confidence,
            "category": category, "module": MODULE}


def analyze_geo_infrastructure(received_result: dict, db_path: Optional[str] = None) -> dict:
    """Resolve M05 hop IPs against the local MMDB; never infer missing data."""
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    provenance = {"database": DB_VERSION, "publisher": "DB-IP.com",
                  "edition": "country-lite", "source_url": "https://db-ip.com/db/download/ip-to-country-lite",
                  "license": "CC BY 4.0", "local_file": path.name}
    hops, findings, out = (received_result or {}).get("chain", []), [], []
    reader = None
    unavailable_reason = None
    if not path.is_file():
        unavailable_reason = "database file missing"
    else:
        try:
            import maxminddb
            reader = maxminddb.open_database(str(path))
        except Exception as exc:  # malformed/corrupt DB and missing reader both degrade honestly
            unavailable_reason = f"database unavailable ({type(exc).__name__})"
    try:
        for hop in hops:
            raw_ip = hop.get("ip")
            if not raw_ip:
                continue
            item = {"hop_number": hop.get("hop_number"), "ip": raw_ip,
                    "country_code": None, "country_name": None, "status": "UNAVAILABLE",
                    "asn": None, "network_owner": None, "reputation": "NOT_ASSESSED",
                    "source_database": DB_VERSION}
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                item["status"] = "INVALID_IP"
                out.append(item)
                continue
            if not ip.is_global:
                item["status"] = "INTERNAL_OR_NON_ROUTABLE"
                findings.append(_finding(len(findings)+1,
                    "Mail hop uses an internal or non-routable IP address", "INFO",
                    f"ip={raw_ip}; hop={hop.get('hop_number')}; no geolocation attempted; source=Python ipaddress classification",
                    "geo:private_ip_hop", "HIGH"))
            elif reader is None:
                item["status"] = "GEOLOCATION_UNAVAILABLE"
                item["unavailable_reason"] = unavailable_reason
            else:
                try:
                    record = reader.get(raw_ip)
                except Exception:
                    record = None
                country = (record or {}).get("country") or {}
                code = country.get("iso_code")
                name = (country.get("names") or {}).get("en")
                if code or name:
                    item.update(status="RESOLVED", country_code=code, country_name=name)
                    findings.append(_finding(len(findings)+1,
                        "Mail hop resolves to probable infrastructure country", "INFO",
                        f"ip={raw_ip}; hop={hop.get('hop_number')}; country={name or code} ({code or 'n/a'}); database={DB_VERSION}",
                        "geo:origin_country", "HIGH"))
                else:
                    item["status"] = "GEOLOCATION_UNAVAILABLE"
                    item["unavailable_reason"] = "IP not present in local database"
            out.append(item)
    finally:
        if reader is not None:
            reader.close()
    resolved = sum(1 for x in out if x["status"] == "RESOLVED")
    return {"module": MODULE, "database": provenance, "database_available": reader is not None,
            "database_error": unavailable_reason, "hop_intelligence": out,
            "findings": findings, "summary": {"hop_ips": len(out), "resolved": resolved,
            "unavailable": sum(1 for x in out if x["status"] == "GEOLOCATION_UNAVAILABLE")},
            "capabilities": {"country": True, "asn": False, "network_owner": False,
                             "whois": False, "live_reputation": False},
            "limitations": ["Country is probable infrastructure location, not sender/person location or actor attribution.",
                            "DB-IP Lite Country contains no ASN, owner, WHOIS, or reputation fields.",
                            "No live API or reputation feed is queried."]}
