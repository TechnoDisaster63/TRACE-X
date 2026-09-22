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
from modules.m17_geo_infra_intel.engine import analyze_geo_infrastructure
from modules.m18_ml_phishing_signal.engine import analyze_ml_phishing_signal
from modules.m07_evidence_engine.engine import build_evidence_bundle
from modules.m08_risk_engine.engine import compute_risk
from modules.m09_threat_graph.engine import build_threat_graph, correlate_campaign, build_sender_trust_graph
from modules.m10_report_generator.engine import generate_report, to_text
from modules.m11_prevention_recommendation.engine import generate_prevention_recommendation
from modules.m11_prevention_recommendation.bec import similarity_matches

logger = get_logger("core.pipeline")


def analyze_email(
    path: str,
    trusted_domains: Optional[List[str]] = None,
    trusted_authserv_ids: Optional[List[str]] = None,
    policies: Optional[List[dict]] = None,
    feedback_records: Optional[List[dict]] = None,
) -> dict:
    """
    Run the full M01-M12 pipeline against a single .eml file.
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
    geo_result = analyze_geo_infrastructure(received_result)
    body_text = "\n".join([parsed.subject or "", parsed.body_plain or "", parsed.body_html_text or ""])
    ml_result = analyze_ml_phishing_signal(body_text)
    sensitive_request = bool(similarity_matches(body_text))
    trust_graph_result = build_sender_trust_graph(
        feedback_records or [], parsed.from_, content_signal_present=sensitive_request
    )

    evidence_bundle = build_evidence_bundle(
        header_result, auth_result, identity_result, received_result, url_result,
        geo_result=geo_result, extra_results={"trust_graph": trust_graph_result, "ml_phishing_signal": ml_result}
    )
    risk_result = compute_risk(evidence_bundle)
    threat_graph = build_threat_graph(evidence_bundle, risk_result, email_id=parsed.from_)
    prevention = generate_prevention_recommendation(
        investigation_id, evidence_bundle, risk_result, threat_graph,
        policies=policies, parsed_email=parsed.to_dict()
    )
    report = generate_report(
        parsed.to_dict(), evidence_bundle, risk_result, threat_graph,
        investigation_id=investigation_id,
        file_name=parsed.source_filename or os.path.basename(str(path)),
        identity_result=identity_result,
        received_result=received_result,
        geo_result=geo_result,
        auth_result=auth_result,
        prevention=prevention,
    )

    elapsed = time.time() - start

    result = {
        "investigation_id": investigation_id,
        "analysis_configuration": {"trusted_domains": sorted(trusted_domains or []), "trusted_authserv_ids": sorted(trusted_authserv_ids or []), "policy_count": len(policies or [])},
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
        "geo_infrastructure": geo_result,
        "ml_phishing_signal": ml_result,
        "sender_trust_graph": trust_graph_result,
        "url_analysis": url_result,
        "evidence": evidence_bundle,
        "risk": risk_result,
        "threat_graph": threat_graph,
        "report": report,
        "prevention": prevention,
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
    policies: Optional[List[dict]] = None,
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
            policies=policies,
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
                "replay": {"batch_only": True, "member_investigation_ids": sorted(m["investigation_id"] for m in camp["related_emails"]), "shared_indicators": camp["shared_indicators"]},
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



def _build_manifest(result: dict, artifact_bytes: Dict[str, bytes], config_snapshot: Optional[dict] = None) -> dict:
    """Build an honest, versioned local manifest. It detects tampering; it is not a signature."""
    import platform
    import subprocess
    from datetime import datetime, timezone
    from core.config import MANIFEST_VERSION
    from core.utils import sha256_bytes
    commit = "UNKNOWN"
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL,
                                         text=True, timeout=2).strip()
    except Exception:
        pass
    artifacts = {name: {"sha256": sha256_bytes(data), "size": len(data)}
                 for name, data in sorted(artifact_bytes.items())}
    graph_hash = result.get("evidence", {}).get("provenance_graph", {}).get("graph_hash", "UNKNOWN")
    return {"manifest_version": MANIFEST_VERSION, "investigation_id": result["investigation_id"],
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "input": {"file": result.get("file"), "sha256": result.get("file_sha256"),
                      "acquisition_mode": "ANALYST_SUPPLIED_FILE"},
            "artifacts": artifacts,
            "tool": {"name": "TRACE-X", "pipeline_version": "M01-M14+M16",
                     "commit": commit, "offline": True, "deterministic_analysis": True},
            "configuration": config_snapshot or result.get("analysis_configuration", {}),
            "environment": {"python": platform.python_version(), "platform": platform.platform()},
            "graph_hash": graph_hash,
            "warnings": ["Integrity manifest only; not a digital signature or chain-of-custody attestation."]}


def save_case(result: dict, case_root: Optional[str] = None, config_snapshot: Optional[dict] = None) -> dict:
    """Publish JSON, text and manifest as one private case directory.

    The case directory is renamed into view only after all staged files are flushed.
    Existing cases are never overwritten. A crash before rename leaves no final case.
    """
    import shutil
    import tempfile
    from core.config import MANIFEST_VERSION, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE
    from core.utils import canonical_json_bytes, private_makedirs, safe_join, sha256_bytes, _fsync_directory
    root = case_root or OUTPUT_DIR
    private_makedirs(root, PRIVATE_DIR_MODE)
    case_name = result["investigation_id"]
    final_dir = safe_join(root, case_name)
    if os.path.exists(final_dir):
        raise FileExistsError(final_dir)
    stage = tempfile.mkdtemp(prefix=f".{case_name}-", dir=root)
    try:
        try: os.chmod(stage, PRIVATE_DIR_MODE)
        except OSError: pass
        json_bytes = json.dumps(result, indent=2, default=str, sort_keys=True).encode("utf-8") + b"\n"
        text_bytes = to_text(result["report"]).encode("utf-8")
        payloads = {f"{case_name}.json": json_bytes, f"{case_name}.txt": text_bytes}
        manifest = _build_manifest(result, payloads, config_snapshot)
        payloads[f"{case_name}.manifest.json"] = canonical_json_bytes(manifest) + b"\n"
        for name, data in payloads.items():
            path = safe_join(stage, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            try: os.chmod(path, PRIVATE_FILE_MODE)
            except OSError: pass
        _fsync_directory(stage)
        os.rename(stage, final_dir)  # same-directory all-or-nothing visibility
        _fsync_directory(root)
        return {"case_dir": final_dir, "json": safe_join(final_dir, f"{case_name}.json"),
                "text": safe_join(final_dir, f"{case_name}.txt"),
                "manifest": safe_join(final_dir, f"{case_name}.manifest.json")}
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def verify_case(case_dir: str) -> dict:
    """Verify manifest schema, names, hashes, sizes and provenance graph hash."""
    from core.utils import canonical_json_bytes, sha256_bytes, sha256_file
    case_dir = os.path.abspath(case_dir)
    manifests = [n for n in os.listdir(case_dir) if n.endswith(".manifest.json")]
    errors = []
    if len(manifests) != 1:
        return {"valid": False, "errors": ["Expected exactly one manifest"], "case_dir": case_dir}
    manifest_path = safe_join(case_dir, manifests[0])
    with open(manifest_path, encoding="utf-8") as stream: manifest = json.load(stream)
    if manifest.get("manifest_version") != "1.0": errors.append("Unsupported manifest version")
    for name, expected in manifest.get("artifacts", {}).items():
        if name != os.path.basename(name) or safe_join(case_dir, name) != os.path.join(case_dir, name):
            errors.append(f"Unsafe artifact name: {name}"); continue
        path = safe_join(case_dir, name)
        if not os.path.isfile(path): errors.append(f"Missing artifact: {name}"); continue
        if os.path.getsize(path) != expected.get("size"): errors.append(f"Size mismatch: {name}")
        if sha256_file(path) != expected.get("sha256"): errors.append(f"SHA-256 mismatch: {name}")
    json_name = f"{manifest.get('investigation_id')}.json"
    json_path = safe_join(case_dir, json_name)
    if os.path.isfile(json_path):
        try:
            with open(json_path, encoding="utf-8") as stream: result = json.load(stream)
            actual_graph = result.get("evidence", {}).get("provenance_graph", {}).get("graph_hash")
            if actual_graph != manifest.get("graph_hash"): errors.append("Provenance graph hash mismatch")
        except (ValueError, OSError) as exc: errors.append(f"Invalid investigation JSON: {exc}")
    return {"valid": not errors, "errors": errors, "case_dir": case_dir,
            "investigation_id": manifest.get("investigation_id"), "manifest": manifest_path}
