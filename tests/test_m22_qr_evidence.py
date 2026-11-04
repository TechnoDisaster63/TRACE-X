"""M22 - optional opt-in offline QR evidence.

Two tiers:
- stdlib-only tests (run everywhere, including CI without the QR runtime):
  fixture integrity, opt-in gating, explicit UNAVAILABLE behaviour.
- runtime tests (skipped when the optional requirements-qr.txt stack is not
  installed): measured fixture recovery and bound enforcement.
"""
import base64
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import analyze_email
from modules.m22_qr_evidence import engine
from modules.m22_qr_evidence.engine import analyze_qr_evidence

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data", "qr")
MANIFEST = json.loads(open(os.path.join(DATA, "manifest.json"), encoding="utf-8").read())
BY_ID = {row["id"]: row for row in MANIFEST}

# The three 38x38px fixtures are below the OpenCV detector limit: valid
# payloads that must NOT decode. Documented limitation, not a silent failure.
TINY_KNOWN_FAIL = {"ordinary_tiny", "structural_tiny", "opaque_tiny"}
EXPECTED_STATUS = {
    "blank": "not_decoded",
    "malformed_png": "malformed",
    "malformed_pdf": "malformed",
    "encrypted_pdf": "encrypted",
    "page_limit": "page_limit",
    "pixel_limit": "pixel_limit",
}

RUNTIME_MISSING = engine._missing_runtime_components()
needs_runtime = pytest.mark.skipif(bool(RUNTIME_MISSING), reason=f"optional QR runtime missing: {RUNTIME_MISSING}")


# ---------- stdlib-only tier ----------

def test_committed_fixtures_match_manifest_hashes():
    for row in MANIFEST:
        path = os.path.join(os.path.dirname(__file__), "..", row["path"])
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        assert digest == row["sha256"], row["id"]


def test_default_pipeline_leaves_qr_evidence_off():
    path = os.path.join(DATA, "ordinary_clean.eml")
    result = analyze_email(path)
    assert "qr_evidence" not in result
    assert "qr_evidence" not in result["analysis_configuration"]


def test_missing_runtime_is_explicit_unavailable(monkeypatch):
    monkeypatch.setattr(engine, "_missing_runtime_components", lambda: ["cv2"])
    result = analyze_qr_evidence(os.path.join(DATA, "ordinary_clean.eml"))
    assert result["available"] is False
    assert result["status"] == "UNAVAILABLE"
    assert result["advisory_only"] is True
    assert result["executable"] is False
    assert result["offline"] is True
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["severity"] == "INFO"
    assert finding["executable"] is False
    assert "cv2" in result["unavailable_reason"]


def test_bounds_are_the_measured_experiment_values():
    assert engine.MAX_PART_BYTES == 2 * 1024 * 1024
    assert engine.MAX_PIXELS == 4_000_000
    assert engine.MAX_PAGES == 3
    assert engine.MAX_PARTS == 8
    assert engine.WALL_TIMEOUT_SECONDS == 10
    assert engine.CPU_LIMIT_SECONDS == 8
    assert engine.ADDRESS_SPACE_LIMIT_BYTES == 1 * 1024 * 1024 * 1024


# ---------- optional-runtime tier ----------

@needs_runtime
@pytest.mark.parametrize("fixture_id", [r["id"] for r in MANIFEST if r["expected"]])
def test_positive_fixture_payload_recovery(fixture_id):
    row = BY_ID[fixture_id]
    result = analyze_qr_evidence(os.path.join(DATA, f"{fixture_id}.eml"))
    got = {item["payload"] for item in result["evidence"]}
    if fixture_id in TINY_KNOWN_FAIL:
        assert got == set()
        assert result["extraction_statuses"][0]["status"] == "not_decoded"
    else:
        assert got == set(row["expected"])
        assert result["extraction_statuses"][0]["status"] == "decoded"
    assert result["available"] is True


@needs_runtime
@pytest.mark.parametrize("fixture_id", sorted(EXPECTED_STATUS))
def test_negative_fixture_explicit_status(fixture_id):
    result = analyze_qr_evidence(os.path.join(DATA, f"{fixture_id}.eml"))
    assert result["evidence"] == []
    statuses = [s["status"] for s in result["extraction_statuses"]]
    assert EXPECTED_STATUS[fixture_id] in statuses


@needs_runtime
def test_byte_limit_status_for_oversize_part(tmp_path):
    oversize = b"\x89PNG\r\n\x1a\n" + b"\0" * (engine.MAX_PART_BYTES + 16)
    body = base64.b64encode(oversize).decode()
    eml = (
        "From: a@example.org\nTo: b@example.org\nSubject: x\n"
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=BB\n\n"
        "--BB\nContent-Type: text/plain\n\nhi\n--BB\n"
        "Content-Type: image/png\nContent-Transfer-Encoding: base64\n"
        f'Content-Disposition: attachment; filename="big.png"\n\n{body}\n--BB--\n'
    )
    path = tmp_path / "byte_limit.eml"
    path.write_text(eml)
    result = analyze_qr_evidence(str(path))
    assert "byte_limit" in [s["status"] for s in result["extraction_statuses"]]


@needs_runtime
def test_payload_url_flag_and_provenance_fields():
    url_result = analyze_qr_evidence(os.path.join(DATA, "ordinary_clean.eml"))
    row = url_result["evidence"][0]
    assert row["is_http_url"] is True
    assert row["payload"] == "https://example.org/info"
    assert row["attachment_sha256"]
    assert row["decoder"].startswith("OpenCV ")
    nonurl = analyze_qr_evidence(os.path.join(DATA, "nonurl.eml"))
    assert nonurl["evidence"][0]["is_http_url"] is False


@needs_runtime
def test_opt_in_pipeline_integrates_info_findings_without_scoring():
    path = os.path.join(DATA, "ordinary_clean.eml")
    baseline = analyze_email(path)
    enabled = analyze_email(path, enable_qr_evidence=True)
    qr = enabled["qr_evidence"]
    assert qr["available"] is True
    assert enabled["analysis_configuration"]["qr_evidence"] == "ENABLED_OPT_IN"
    assert {f["category"] for f in qr["findings"]} == {"QR_EVIDENCE"}
    assert all(f["severity"] == "INFO" and f["executable"] is False for f in qr["findings"])
    # QR evidence enters the bundle as evidence nodes...
    bundled = [e for e in enabled["evidence"]["evidence"] if e.get("category") == "QR_EVIDENCE"]
    assert bundled and all(e["severity"] == "INFO" for e in bundled)
    # ...and never moves the deterministic rule score (INFO carries 0 points).
    assert enabled["risk"]["score"] == baseline["risk"]["score"]
    assert enabled["risk"]["risk_level"] == baseline["risk"]["risk_level"]
