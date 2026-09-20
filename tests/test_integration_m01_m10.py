"""
Full M01 -> M10 pipeline integration test, run via core.pipeline.analyze_email
against every synthetic sample in test_data/. Verifies the pipeline never
crashes end-to-end (including the new M09 Threat Graph and M10 Report
Generator stages) and that report artifacts are internally consistent
with the upstream risk assessment.
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import analyze_email, save_investigation, save_report_text
from modules.m10_report_generator.engine import to_text, to_json

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_pipeline_runs_end_to_end_with_m09_m10_on_every_sample():
    all_eml = glob.glob(os.path.join(DATA, "**", "*.eml"), recursive=True)
    assert len(all_eml) >= 10
    for path in all_eml:
        result = analyze_email(path)
        for key in ("investigation_id", "file", "file_sha256", "header_forensics",
                    "authentication", "identity", "received_chain", "url_analysis",
                    "evidence", "risk", "threat_graph", "report"):
            assert key in result, f"{key} missing for {path}"


def test_threat_graph_consistent_with_risk():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    assert result["threat_graph"]["risk_score"] == result["risk"]["score"]
    assert result["threat_graph"]["risk_level"] == result["risk"]["risk_level"]


def test_report_consistent_with_risk_and_graph():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    assert result["report"]["risk_score"] == result["risk"]["score"]
    assert result["report"]["threat_class"] == result["threat_graph"]["threat_class"]


def test_report_json_and_text_never_raise():
    for rel in ["legitimate/legit_newsletter.eml", "phishing/lookalike_domain.eml",
                "malformed/malformed_empty.eml", "malformed/malformed_truncated.eml"]:
        result = analyze_email(p(rel))
        text = to_text(result["report"])
        j = to_json(result["report"])
        assert isinstance(text, str) and len(text) > 0
        parsed = json.loads(j)
        assert parsed["risk_score"] == result["risk"]["score"]


def test_clean_email_full_pipeline_clean_classification():
    result = analyze_email(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    assert result["risk"]["score"] == 0
    assert result["threat_graph"]["threat_class"] == "CLEAN"


def test_save_investigation_and_report_text(tmp_path):
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    out_dir = str(tmp_path / "output")
    reports_dir = str(tmp_path / "reports")
    json_path = save_investigation(result, output_dir=out_dir)
    text_path = save_report_text(result, reports_dir=reports_dir)
    assert os.path.isfile(json_path)
    assert os.path.isfile(text_path)
    with open(json_path) as f:
        saved = json.load(f)
    assert saved["risk"]["score"] == result["risk"]["score"]
    with open(text_path) as f:
        text_content = f.read()
    assert "TRACE-X ANALYSIS REPORT" in text_content


def test_malformed_and_empty_do_not_crash_m09_m10():
    for rel in ["malformed/malformed_empty.eml", "malformed/malformed_truncated.eml"]:
        result = analyze_email(p(rel))
        assert result["threat_graph"] is not None
        assert result["report"] is not None
