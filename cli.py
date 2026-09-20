#!/usr/bin/env python3
"""
TRACE-X CLI Prototype (M01-M10)

Usage:
    python cli.py analyze <path/to/email.eml>
    python cli.py analyze-folder <path/to/folder>
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pipeline import analyze_email, analyze_campaign, save_investigation, save_report_text

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
    result = analyze_email(args.path, trusted_domains=args.trusted_domains or [])
    out_path = save_investigation(result)
    report_path = save_report_text(result)
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
            result = analyze_email(path, trusted_domains=args.trusted_domains or [])
            save_investigation(result)
            save_report_text(result)
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
    batch = analyze_campaign(eml_files, trusted_domains=args.trusted_domains or [])
    for inv in batch["investigations"]:
        save_investigation(inv)
        save_report_text(inv)
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


def main():
    parser = argparse.ArgumentParser(prog="cli.py", description="TRACE-X Email Forensic Investigation CLI")
    sub = parser.add_subparsers(dest="command")

    p_analyze = sub.add_parser("analyze", help="Analyze a single .eml file")
    p_analyze.add_argument("path", help="Path to .eml file")
    p_analyze.add_argument("--trusted-domains", nargs="*", default=[], dest="trusted_domains",
                            help="Optional list of trusted domains for identity analysis")
    p_analyze.set_defaults(func=cmd_analyze)

    p_folder = sub.add_parser("analyze-folder", help="Analyze all .eml files in a folder")
    p_folder.add_argument("folder", help="Path to folder containing .eml files")
    p_folder.add_argument("--trusted-domains", nargs="*", default=[], dest="trusted_domains")
    p_folder.set_defaults(func=cmd_analyze_folder)

    p_campaign = sub.add_parser("campaign", help="Analyze all .eml files in a folder AND correlate them into campaigns")
    p_campaign.add_argument("folder", help="Path to folder containing .eml files")
    p_campaign.add_argument("--trusted-domains", nargs="*", default=[], dest="trusted_domains")
    p_campaign.set_defaults(func=cmd_campaign)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
