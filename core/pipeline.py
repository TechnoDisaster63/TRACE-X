"""
core/pipeline.py

Wires M01 -> M02 -> M03 -> M04 -> M05 -> M06 -> M07 -> M08 -> M09 -> M10
into a single analyze_email() call. This is the integration layer that runs
the full prototype end-to-end. No frontend, no API, no DB.
"""
import json
import os
import time
from typing import Dict, List, Optional

from core.utils import get_logger, next_investigation_id, safe_join
from core.config import OUTPUT_DIR, REPORTS_DIR

from modules.m01_eml_parser.parser import parse_eml
from modules.m02_header_forensics.analyzer import analyze_headers
from modules.m03_auth_analyzer.analyzer import analyze_authentication
from modules.m04_identity_analyzer.analyzer import analyze_identity
from modules.m05_received_chain.analyzer import analyze_received_chain
from modules.m06_url_analyzer.analyzer import analyze_urls
from modules.m07_evidence_engine.engine import build_evidence_bundle
from modules.m08_risk_engine.engine import compute_risk
from modules.m09_threat_graph.engine import build_threat_graph, correlate_campaign
from modules.m10_report_generator.engine import generate_report, to_text

logger = get_logger("core.pipeline")


def analyze_email(
    path: str,
    trusted_domains: Optional[List[str]] = None,
    trusted_authserv_ids: Optional[List[str]] = None,
) -> dict:
    """
    Run the full M01-M10 pipeline against a single .eml file.
    Returns a single JSON-serializable investigation result.

    A single, unique investigation_id is generated once here and
    propagated unchanged through every module (M01-M10) and into the
    saved JSON/report/text output for this investigation.
    """
    start = time.time()
    investigation_id = next_investigation_id(state_dir=OUTPUT_DIR)

    parsed = parse_eml(path)

    header_result = analyze_headers(parsed)
    auth_result = analyze_authentication(parsed, trusted_authserv_ids=trusted_authserv_ids)
    identity_result = analyze_identity(parsed, trusted_domains=trusted_domains)
    received_result = analyze_received_chain(parsed)
    url_result = analyze_urls(parsed)

    evidence_bundle = build_evidence_bundle(
        header_result, auth_result, identity_result, received_result, url_result
    )
    risk_result = compute_risk(evidence_bundle)
    threat_graph = build_threat_graph(evidence_bundle, risk_result, email_id=parsed.from_)
    report = generate_report(
        parsed.to_dict(), evidence_bundle, risk_result, threat_graph,
        investigation_id=investigation_id,
        file_name=parsed.source_filename or os.path.basename(str(path)),
        identity_result=identity_result,
        received_result=received_result,
        auth_result=auth_result,
    )

    elapsed = time.time() - start

    result = {
        "investigation_id": investigation_id,
        "file": parsed.source_filename or os.path.basename(str(path)),
        "file_sha256": parsed.file_sha256,
        "parse_warnings": parsed.parse_warnings,
        "email_summary": {
            "from": parsed.from_,
            "to": parsed.to,
            "subject": parsed.subject,
            "date": parsed.date,
        },
        "header_forensics": header_result,
        "authentication": auth_result,
        "identity": identity_result,
        "received_chain": received_result,
        "url_analysis": url_result,
        "evidence": evidence_bundle,
        "risk": risk_result,
        "threat_graph": threat_graph,
        "report": report,
        "processing_time_seconds": round(elapsed, 4),
    }
    return result


def save_investigation(result: dict, output_dir: str = OUTPUT_DIR) -> str:
    os.makedirs(output_dir, exist_ok=True)
    out_path = safe_join(output_dir, f"{result['investigation_id']}.json")
    with open(out_path, "x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return out_path


def save_report_text(result: dict, reports_dir: str = REPORTS_DIR) -> str:
    """Save the M10 human-readable text report alongside the JSON investigation."""
    os.makedirs(reports_dir, exist_ok=True)
    out_path = safe_join(reports_dir, f"{result['investigation_id']}.txt")
    with open(out_path, "x", encoding="utf-8") as f:
        f.write(to_text(result["report"]))
    return out_path


def analyze_campaign(
    paths: List[str],
    trusted_domains: Optional[List[str]] = None,
    trusted_authserv_ids: Optional[List[str]] = None,
) -> dict:
    """
    Analyze multiple .eml files individually (each gets its own unique
    investigation_id, per analyze_email()) and then run M09 campaign
    correlation across the resulting investigations.

    Each investigation's `report.campaign_relationships` is populated with
    real correlation output for THAT specific email (or a "not part of a
    campaign" note when it wasn't grouped with anything).

    Returns:
        {
          "investigations": [<full analyze_email() result>, ...],
          "campaign_correlation": <correlate_campaign() result>,
        }
    """
    investigations = [
        analyze_email(
            p,
            trusted_domains=trusted_domains,
            trusted_authserv_ids=trusted_authserv_ids,
        )
        for p in paths
    ]
    correlation = correlate_campaign(investigations)

    campaign_by_investigation_id: Dict[str, dict] = {}
    for camp in correlation["campaigns"]:
        for member in camp["related_emails"]:
            campaign_by_investigation_id[member["investigation_id"]] = {
                "campaign_id": camp["campaign_id"],
                "is_part_of_campaign": True,
                "related_email_count": camp["related_email_count"],
                "shared_indicators": camp["shared_indicators"],
                "correlation_score": camp["correlation_score"],
                "confidence": camp["confidence"],
                "evidence": camp["evidence"],
            }

    # Re-attach campaign context into each investigation's report so the
    # saved JSON/text report for a single email reflects its real campaign
    # membership (or lack of one) from this batch.
    for inv in investigations:
        camp_ctx = campaign_by_investigation_id.get(inv["investigation_id"])
        if camp_ctx:
            inv["report"]["campaign_relationships"] = camp_ctx
        # else: leave the default "not part of a campaign" note already set

    return {
        "investigations": investigations,
        "campaign_correlation": correlation,
    }
