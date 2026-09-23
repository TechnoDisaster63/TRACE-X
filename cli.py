#!/usr/bin/env python3
"""
TRACE-X CLI Prototype (M01-M14 + M16 + M17 + M18)

Usage:
    python cli.py analyze <path/to/email.eml>
    python cli.py analyze-folder <path/to/folder>
"""
import argparse
import glob
import json
from datetime import datetime, timezone
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pipeline import analyze_email, analyze_campaign, save_case, verify_case
from modules.m13_ioc_export.engine import build_ioc_export, to_json as ioc_to_json, to_csv as ioc_to_csv
from modules.m14_analyst_feedback.engine import create_feedback_record
from modules.m16_prevention_audit.lifecycle import create_lifecycle, transition_lifecycle
from modules.m19_audit_chain.engine import append_event, verify_chain
from modules.m20_case_store.store import CaseStore
from modules.m21_folder_ingest.watcher import watch

SEVERITY_TAG = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "INFO": "[INFO]"}


def _print_result(result: dict):
    print("=" * 60)
    print("TRACE-X EMAIL INVESTIGATION")
    print("=" * 60)
    print()
    print(f"Investigation ID:\n{result['investigation_id']}")
    print()
    print(f"File:\n{result['file']}")
    print()
    print(f"SHA-256:\n{result['file_sha256']}")
    print()
    risk = result["risk"]
    print(f"RISK:\n{risk['risk_level']}  (score: {risk['score']}/100)")
    print()
    tg = result["threat_graph"]
    print(f"THREAT CLASSIFICATION:\n{tg['threat_class']}  (confidence: {tg['threat_class_confidence']})")
    print()
    print("TOP FINDINGS:")
    top = sorted(
        result["evidence"]["evidence"],
        key=lambda e: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[e["severity"]],
        reverse=True,
    )[:6]
    if not top:
        print("  (none)")
    for item in top:
        print(f"  {SEVERITY_TAG.get(item['severity'], '')} {item['finding']}")
    print()
    print(f"EVIDENCE COUNT:\n{result['evidence']['total_evidence_count']}")
    print()
    print(f"CONFIDENCE:\n{risk['confidence']}")
    print()
    if result["parse_warnings"]:
        print("PARSE WARNINGS:")
        for w in result["parse_warnings"]:
            print(f"  - {w}")
        print()


def cmd_analyze(args):
    if not os.path.isfile(args.path):
        print(f"ERROR: file not found: {args.path}")
        sys.exit(1)
    result = analyze_email(
        args.path,
        trusted_domains=args.trusted_domains or [],
        trusted_authserv_ids=args.trusted_authserv_ids or [],
    )
    case = save_case(result)
    CaseStore(args.case_db).add(result)
    append_event(args.audit_log, actor=args.actor, action="ANALYZE_EMAIL", investigation_id=result["investigation_id"], input_sha256=result["file_sha256"], details={"source": "CLI", "case_dir": case["case_dir"]})
    out_path = case["json"]
    report_path = case["text"]
    _print_result(result)
    print(f"REPORT DATA SAVED:\n{out_path}")
    print(f"TEXT REPORT SAVED:\n{report_path}")
    print("=" * 60)


def cmd_analyze_folder(args):
    if not os.path.isdir(args.folder):
        print(f"ERROR: folder not found: {args.folder}")
        sys.exit(1)
    eml_files = sorted(glob.glob(os.path.join(args.folder, "**", "*.eml"), recursive=True))
    if not eml_files:
        print(f"No .eml files found under {args.folder}")
        return
    print(f"Found {len(eml_files)} .eml file(s) under {args.folder}\n")
    for path in eml_files:
        try:
            result = analyze_email(
                path,
                trusted_domains=args.trusted_domains or [],
                trusted_authserv_ids=args.trusted_authserv_ids or [],
            )
            save_case(result)
            _print_result(result)
        except Exception as e:
            print(f"ERROR analyzing {path}: {e}")


def cmd_campaign(args):
    if not os.path.isdir(args.folder):
        print(f"ERROR: folder not found: {args.folder}")
        sys.exit(1)
    eml_files = sorted(glob.glob(os.path.join(args.folder, "**", "*.eml"), recursive=True))
    if len(eml_files) < 2:
        print(f"Need at least 2 .eml files under {args.folder} to correlate a campaign "
              f"(found {len(eml_files)}).")
        return
    print(f"Found {len(eml_files)} .eml file(s) under {args.folder}\n")
    batch = analyze_campaign(
        eml_files,
        trusted_domains=args.trusted_domains or [],
        trusted_authserv_ids=args.trusted_authserv_ids or [],
    )
    for inv in batch["investigations"]:
        save_case(inv)
        _print_result(inv)

    correlation = batch["campaign_correlation"]
    print("=" * 60)
    print("CAMPAIGN CORRELATION")
    print("=" * 60)
    print(f"Total investigations: {correlation['total_investigations']}")
    print(f"Campaigns found: {len(correlation['campaigns'])}")
    for camp in correlation["campaigns"]:
        print()
        print(f"Campaign ID: {camp['campaign_id']}")
        print(f"Related emails ({camp['related_email_count']}):")
        for m in camp["related_emails"]:
            print(f"  - {m['investigation_id']}  {m['file']}")
        print(f"Correlation score: {camp['correlation_score']}/100")
        print(f"Confidence: {camp['confidence']}")
        print("Evidence:")
        for e in camp["evidence"]:
            print(f"  - {e}")
    if correlation["uncorrelated"]:
        print()
        print(f"Not correlated with any other email: {', '.join(correlation['uncorrelated'])}")
    print("=" * 60)



def cmd_verify(args):
    verification = verify_case(args.case_dir)
    print("VALID" if verification["valid"] else "INVALID")
    for error in verification["errors"]:
        print(f"  - {error}")
    if not verification["valid"]:
        sys.exit(2)


def _load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)

def cmd_export_ioc(args):
    investigation = _load_json(args.investigation)
    observed = args.observed_at or datetime.now(timezone.utc).isoformat()
    export = build_ioc_export(investigation, observed)
    text = ioc_to_csv(export) if args.format == "csv" else ioc_to_json(export)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as handle: handle.write(text)
        print(args.output)
    else: print(text)

def cmd_feedback(args):
    investigation = _load_json(args.investigation)
    record = create_feedback_record(args.decision, args.actor, args.actor_role,
        args.decided_at or datetime.now(timezone.utc).isoformat(), args.reason,
        investigation, investigation["prevention"],
        rule_versions=args.rule_versions or ["TRACE-X-M14-1"], details={"sender": args.sender} if args.sender else {})
    print(json.dumps(record.to_dict(), indent=2))

def cmd_lifecycle(args):
    investigation = _load_json(args.investigation)
    now = args.timestamp or datetime.now(timezone.utc).isoformat()
    lifecycle = create_lifecycle(investigation["prevention"], args.actor, args.actor_role, now, args.reason)
    if args.transition:
        lifecycle = transition_lifecycle(lifecycle, args.transition, args.actor, args.actor_role, now,
                                         args.reason, json.loads(args.details or "{}"))
    print(json.dumps(lifecycle.to_dict(), indent=2))


def cmd_verify_audit(args):
    result = verify_chain(args.audit_log)
    print(json.dumps(result, indent=2))
    if not result["valid"]: sys.exit(2)

def cmd_correlate_history(args):
    result = CaseStore(args.case_db).correlate()
    print(json.dumps(result, indent=2))

def cmd_watch(args):
    if not os.path.isdir(args.folder):
        print(f"ERROR: folder not found: {args.folder}"); sys.exit(1)
    watch(args.folder, db_path=args.case_db, audit_path=args.audit_log, actor=args.actor, interval=args.interval)

def main():
    parser = argparse.ArgumentParser(prog="cli.py", description="TRACE-X Email Forensic Investigation CLI")
    sub = parser.add_subparsers(dest="command")

    p_analyze = sub.add_parser("analyze", help="Analyze a single .eml file")
    p_analyze.add_argument("path", help="Path to .eml file")
    p_analyze.add_argument("--trusted-domains", nargs="*", default=[], dest="trusted_domains",
                            help="Optional list of trusted domains for identity analysis")
    p_analyze.add_argument("--trusted-authserv-ids", nargs="*", default=[], dest="trusted_authserv_ids",
                            help="Explicit trusted Authentication-Results authserv-id allowlist")
    p_analyze.add_argument("--actor", default=os.environ.get("TRACE_X_ACTOR", "LOCAL_ANALYST"))
    p_analyze.add_argument("--audit-log", default=os.environ.get("TRACE_X_AUDIT_LOG", "output/audit-chain.jsonl"), dest="audit_log")
    p_analyze.add_argument("--case-db", default=os.environ.get("TRACE_X_CASE_DB", "output/cases.sqlite3"), dest="case_db")
    p_analyze.set_defaults(func=cmd_analyze)

    p_folder = sub.add_parser("analyze-folder", help="Analyze all .eml files in a folder")
    p_folder.add_argument("folder", help="Path to folder containing .eml files")
    p_folder.add_argument("--trusted-domains", nargs="*", default=[], dest="trusted_domains")
    p_folder.add_argument("--trusted-authserv-ids", nargs="*", default=[], dest="trusted_authserv_ids")
    p_folder.set_defaults(func=cmd_analyze_folder)

    p_campaign = sub.add_parser("campaign", help="Analyze all .eml files in a folder AND correlate them into campaigns")
    p_campaign.add_argument("folder", help="Path to folder containing .eml files")
    p_campaign.add_argument("--trusted-domains", nargs="*", default=[], dest="trusted_domains")
    p_campaign.add_argument("--trusted-authserv-ids", nargs="*", default=[], dest="trusted_authserv_ids")
    p_campaign.set_defaults(func=cmd_campaign)

    p_verify = sub.add_parser("verify-case", help="Verify a saved case manifest and artifacts")
    p_verify.add_argument("case_dir", help="Path to one saved case directory")
    p_verify.set_defaults(func=cmd_verify)


    p_ioc = sub.add_parser("export-ioc", help="Export offline evidence-backed IOCs")
    p_ioc.add_argument("investigation")
    p_ioc.add_argument("--format", choices=("json", "csv"), default="json")
    p_ioc.add_argument("--output")
    p_ioc.add_argument("--observed-at", dest="observed_at")
    p_ioc.set_defaults(func=cmd_export_ioc)

    p_feedback = sub.add_parser("feedback", help="Create immutable analyst feedback JSON")
    p_feedback.add_argument("investigation")
    p_feedback.add_argument("--decision", required=True)
    p_feedback.add_argument("--actor", required=True)
    p_feedback.add_argument("--actor-role", default="ANALYST", dest="actor_role")
    p_feedback.add_argument("--reason", required=True)
    p_feedback.add_argument("--decided-at", dest="decided_at")
    p_feedback.add_argument("--sender")
    p_feedback.add_argument("--rule-versions", nargs="*", dest="rule_versions")
    p_feedback.set_defaults(func=cmd_feedback)

    p_lifecycle = sub.add_parser("lifecycle", help="Create/transition advisory audit lifecycle")
    p_lifecycle.add_argument("investigation")
    p_lifecycle.add_argument("--transition")
    p_lifecycle.add_argument("--actor", required=True)
    p_lifecycle.add_argument("--actor-role", default="ANALYST", dest="actor_role")
    p_lifecycle.add_argument("--timestamp")
    p_lifecycle.add_argument("--reason", required=True)
    p_lifecycle.add_argument("--details", help="JSON object for transition details")
    p_lifecycle.set_defaults(func=cmd_lifecycle)

    p_audit = sub.add_parser("verify-audit", help="Verify the append-only hash-chained audit journal")
    p_audit.add_argument("--audit-log", default=os.environ.get("TRACE_X_AUDIT_LOG", "output/audit-chain.jsonl"), dest="audit_log")
    p_audit.set_defaults(func=cmd_verify_audit)

    p_history = sub.add_parser("correlate-history", help="Correlate all cases in the persistent local store")
    p_history.add_argument("--case-db", default=os.environ.get("TRACE_X_CASE_DB", "output/cases.sqlite3"), dest="case_db")
    p_history.set_defaults(func=cmd_correlate_history)

    p_watch = sub.add_parser("watch-folder", help="Continuously ingest new .eml files from a local folder")
    p_watch.add_argument("folder")
    p_watch.add_argument("--actor", default=os.environ.get("TRACE_X_ACTOR", "WATCHER"))
    p_watch.add_argument("--interval", type=float, default=2.0)
    p_watch.add_argument("--audit-log", default=os.environ.get("TRACE_X_AUDIT_LOG", "output/audit-chain.jsonl"), dest="audit_log")
    p_watch.add_argument("--case-db", default=os.environ.get("TRACE_X_CASE_DB", "output/cases.sqlite3"), dest="case_db")
    p_watch.set_defaults(func=cmd_watch)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()

