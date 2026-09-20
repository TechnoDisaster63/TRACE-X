from pathlib import Path

REQUIRED = [
    "PREVENTION_ARCHITECTURE.md", "PREVENTION_ENGINE_SPECIFICATION.md",
    "TRUST_POLICY_SPECIFICATION.md", "ACTION_LIFECYCLE.md", "SECURITY_MODEL.md",
    "THREAT_MODEL.md", "EVIDENCE_AND_AUDIT_MODEL.md", "PREVENTION_API_SPECIFICATION.md",
    "TEST_PLAN.md", "SECURITY_TEST_RESULTS.md", "LIMITATIONS_AND_NON_GOALS.md",
    "IMPLEMENTATION_STATUS.md", "ROADMAP.md", "CHANGELOG.md", "HACKATHON_DEMO.md",
    "FINAL_TECHNICAL_REPORT.md",
]

def test_required_documents_exist_and_are_nonempty():
    for name in REQUIRED:
        path = Path(name)
        assert path.is_file(), name
        assert path.stat().st_size > 150, name


def test_readiness_report_rejects_unsupported_production_claim():
    text = Path("FINAL_TECHNICAL_REPORT.md").read_text()
    assert "Production readiness: NOT READY" in text
    assert "Integration readiness: DESIGN/EXPORT READY ONLY" in text


def test_api_spec_states_no_network_api():
    text = Path("PREVENTION_API_SPECIFICATION.md").read_text()
    assert "There is no network API" in text
