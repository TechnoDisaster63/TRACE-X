import os
from pathlib import Path
import pytest
from core.config import MAX_EML_SIZE_BYTES, MAX_URLS_PER_EMAIL, MAX_RECEIVED_HOPS
from core.pipeline import save_investigation
from core.utils import next_investigation_id
from modules.m01_eml_parser.parser import parse_eml
from modules.m06_url_analyzer.analyzer import _analyze_single_url

def test_bytes_input_size_limit():
    with pytest.raises(ValueError, match="size limit"):
        parse_eml(b"A" * (MAX_EML_SIZE_BYTES + 1))

def test_url_and_received_limits():
    raw = ("From: a@b.com\nMessage-ID: <x>\nDate: Tue, 1 Jan 2026 00:00:00 +0000\n" +
           "".join(f"Received: from h{i}.example by mx.example\n" for i in range(MAX_RECEIVED_HOPS + 10)) +
           "\n" + " ".join(f"https://x{i}.example/a" for i in range(MAX_URLS_PER_EMAIL + 10))).encode()
    parsed = parse_eml(raw)
    assert len(parsed.urls) == MAX_URLS_PER_EMAIL
    assert len(parsed.received) == MAX_RECEIVED_HOPS
    assert any("truncated" in warning for warning in parsed.parse_warnings)

def test_shortener_requires_domain_boundary():
    assert "shortening" not in " ".join(_analyze_single_url("https://bit.ly.evil.example/a")["signals"]).lower()
    assert "shortening" in " ".join(_analyze_single_url("https://go.bit.ly/a")["signals"]).lower()

def test_counter_recovers_from_existing_outputs(tmp_path):
    (tmp_path / "TX-000123.json").write_text("{}")
    assert next_investigation_id(str(tmp_path)) == "TX-000124"

def test_save_refuses_overwrite(tmp_path):
    result = {"investigation_id": "TX-000001"}
    save_investigation(result, str(tmp_path))
    with pytest.raises(FileExistsError):
        save_investigation(result, str(tmp_path))

def test_atomic_write_new_works_without_fchmod(monkeypatch, tmp_path):
    """Windows has no os.fchmod; path chmod must preserve the safe write."""
    import core.utils as utils

    monkeypatch.delattr(utils.os, "fchmod", raising=False)
    target = tmp_path / "case.json"
    utils.atomic_write_new(str(target), b'{"ok":true}')
    assert target.read_bytes() == b'{"ok":true}'
