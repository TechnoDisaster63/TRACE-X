import json, os, stat
from concurrent.futures import ThreadPoolExecutor
import pytest
from core.pipeline import analyze_email, save_case, verify_case
from modules.m07_evidence_engine.engine import build_evidence_bundle

ROOT = os.path.dirname(os.path.dirname(__file__))
def sample(name): return os.path.join(ROOT, "test_data", name)

def test_stable_ids_and_multi_origin_are_order_independent():
    finding = {"finding_id":"A","finding":"same","severity":"HIGH","evidence":"x",
               "source":"header:x","confidence":"MEDIUM","category":"IDENTITY"}
    empty = {"findings":[],"summary":{}}
    a = {"findings":[finding, dict(finding, finding_id="B")],"summary":{}}
    b = {"findings":list(reversed(a["findings"])),"summary":{}}
    one = build_evidence_bundle(a, empty, empty, empty, empty)
    two = build_evidence_bundle(b, empty, empty, empty, empty)
    assert one["evidence"][0]["evidence_id"] == two["evidence"][0]["evidence_id"]
    assert sorted(one["evidence"][0]["supporting_finding_ids"]) == ["A", "B"]
    assert one["provenance_graph"]["graph_hash"] == two["provenance_graph"]["graph_hash"]

def test_dimensions_are_separate_and_auth_is_reported():
    result = analyze_email(sample("phishing/phishing_paypal_lookalike.eml"))
    item = next((x for x in result["evidence"]["evidence"] if "authentication_provenance" in x), None)
    assert item is not None
    assert item["observation_status"] == "REPORTED"
    assert item["authentication_provenance"]["independently_verified"] is False
    assert {"source_reliability","analytic_confidence","severity"} <= set(item)
    assert result["prevention"]["executable"] is False

def test_atomic_private_case_and_tamper_detection(tmp_path):
    result = analyze_email(sample("legitimate/legit_newsletter.eml"))
    paths = save_case(result, str(tmp_path))
    assert verify_case(paths["case_dir"])["valid"]
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(paths["json"]).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(paths["case_dir"]).st_mode) == 0o700
    with open(paths["text"], "ab") as f: f.write(b"tamper")
    verification = verify_case(paths["case_dir"])
    assert not verification["valid"]
    assert any("mismatch" in x.lower() for x in verification["errors"])

def test_publish_failure_leaves_no_final_case(tmp_path, monkeypatch):
    result = analyze_email(sample("legitimate/legit_newsletter.eml"))
    import core.pipeline as pipeline
    real_open = os.open
    count = {"n":0}
    def fail_second(path, flags, *args, **kwargs):
        if ".trace-x" not in str(path) and str(path).endswith(".txt"):
            raise OSError("injected")
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(pipeline.os, "open", fail_second)
    with pytest.raises(OSError): save_case(result, str(tmp_path))
    assert not (tmp_path / result["investigation_id"]).exists()
    assert not list(tmp_path.glob(f".{result['investigation_id']}-*"))

def test_concurrent_same_case_only_one_wins(tmp_path):
    result = analyze_email(sample("legitimate/legit_newsletter.eml"))
    def attempt():
        try: save_case(result, str(tmp_path)); return "ok"
        except (FileExistsError, OSError): return "blocked"
    with ThreadPoolExecutor(max_workers=2) as pool: outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == ["blocked", "ok"]
    assert verify_case(str(tmp_path / result["investigation_id"]))["valid"]
