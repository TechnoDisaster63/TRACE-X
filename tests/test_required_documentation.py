from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "docs/architecture/PREVENTION_ARCHITECTURE.md", "docs/specifications/PREVENTION_ENGINE_SPECIFICATION.md",
    "docs/specifications/TRUST_POLICY_SPECIFICATION.md", "docs/specifications/ACTION_LIFECYCLE.md", "docs/security/SECURITY_MODEL.md",
    "docs/security/THREAT_MODEL.md", "docs/architecture/EVIDENCE_AND_AUDIT_MODEL.md", "docs/specifications/PREVENTION_API_SPECIFICATION.md",
    "docs/testing/TEST_PLAN.md", "docs/testing/SECURITY_TEST_RESULTS.md", "docs/security/LIMITATIONS_AND_NON_GOALS.md",
    "docs/project/IMPLEMENTATION_STATUS.md", "docs/project/ROADMAP.md", "docs/project/CHANGELOG.md", "docs/guides/HACKATHON_DEMO.md",
    "docs/reports/FINAL_TECHNICAL_REPORT.md",
]

def test_required_documents_exist_and_are_nonempty():
    for name in REQUIRED:
        path = ROOT / name
        assert path.is_file(), name
        assert path.stat().st_size > 150, name


def test_readiness_report_rejects_unsupported_production_claim():
    text = (ROOT / "docs/reports/FINAL_TECHNICAL_REPORT.md").read_text()
    assert "Production readiness: NOT READY" in text
    assert "Integration readiness: DESIGN/EXPORT READY ONLY" in text


def test_api_spec_states_no_network_api():
    text = (ROOT / "docs/specifications/PREVENTION_API_SPECIFICATION.md").read_text()
    assert "There is no network API" in text
