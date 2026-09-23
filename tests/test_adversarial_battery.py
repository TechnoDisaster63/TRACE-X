from pathlib import Path

from core.pipeline import analyze_email, save_case, verify_case

FIXTURES = Path(__file__).parents[1] / "adversarial_inputs"


def test_malformed_email_is_bounded_not_a_crash():
    result = analyze_email(str(FIXTURES / "malformed.eml"))
    assert result["risk"]["score"] == 30
    assert result["risk"]["risk_level"] == "MEDIUM"
    assert any("No Received headers" in e["finding"] for e in result["evidence"]["evidence"])


def test_forged_received_headers_are_not_treated_as_authenticated():
    result = analyze_email(str(FIXTURES / "forged-received.eml"))
    assert result["risk"]["score"] == 9
    assert result["risk"]["risk_level"] == "LOW"
    assert not result.get("trusted_received_chain")


def test_tampered_case_artifact_fails_hash_verification(tmp_path):
    result = analyze_email(str(FIXTURES / "forged-received.eml"))
    case = save_case(result, case_root=str(tmp_path))
    text = Path(case["text"])
    text.write_bytes(text.read_bytes() + b"\nTAMPERED\n")
    check = verify_case(case["case_dir"])
    assert check["valid"] is False
    assert any("SHA-256 mismatch" in error for error in check["errors"])


def test_boring_business_email_stays_low_risk():
    result = analyze_email(str(FIXTURES / "boring-business.eml"))
    assert result["risk"]["risk_level"] == "LOW"
    assert result["risk"]["score"] == 27
