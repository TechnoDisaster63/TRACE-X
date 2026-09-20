import csv
import io
import json
import os

import pytest

from core.pipeline import analyze_email
from modules.m13_ioc_export.engine import IOCExportError, build_ioc_export, to_csv, to_json

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")
OBSERVED = "2026-09-20T17:30:00+00:00"


def p(rel):
    return os.path.join(DATA, rel)


def phishing_export():
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    return result, build_ioc_export(result, OBSERVED)


def test_export_is_evidence_backed_and_traceable():
    result, export = phishing_export()
    evidence_ids = {e["evidence_id"] for e in result["evidence"]["evidence"]}
    assert export["indicator_count"] >= 1
    for item in export["indicators"]:
        assert item["source_investigation_id"] == result["investigation_id"]
        assert item["evidence_id"] in evidence_ids
        assert item["reason"]
        assert item["source_module"]


def test_export_marks_confidence_as_non_probability_and_no_automation():
    _, export = phishing_export()
    assert export["execution"]["automated_enforcement_allowed"] is False
    assert export["execution"]["external_actions"] is False
    assert all(item["confidence_label"] in {"LOW", "MEDIUM", "HIGH"} for item in export["indicators"])
    assert all(item["confidence_is_probability"] is False for item in export["indicators"])
    assert all(item["safe_for_automated_enforcement"] is False for item in export["indicators"])


def test_verification_status_is_truthful():
    _, export = phishing_export()
    assert all(item["verification_status"] in {"HEURISTIC_OR_REPORTED", "VERIFIED"} for item in export["indicators"])
    assert all(item["verification_status"] == "HEURISTIC_OR_REPORTED" for item in export["indicators"])


def test_timestamps_review_and_expiration_are_deterministic():
    _, export = phishing_export()
    for item in export["indicators"]:
        assert item["observed_at"] == "2026-09-20T17:30:00+00:00"
        assert item["review_after"] == "2026-10-20T17:30:00+00:00"
        assert item["expires_at"] == "2026-12-19T17:30:00+00:00"


def test_json_is_deterministic_for_same_investigation_and_time():
    result, first = phishing_export()
    second = build_ioc_export(result, OBSERVED)
    assert to_json(first) == to_json(second)
    assert json.loads(to_json(first))["format_note"] == "TRACE-X JSON/CSV; not STIX"


def test_csv_is_deterministic_and_round_trips_rows():
    _, export = phishing_export()
    first = to_csv(export)
    assert first == to_csv(export)
    rows = list(csv.DictReader(io.StringIO(first)))
    assert len(rows) == export["indicator_count"]
    assert all(row["safe_for_automated_enforcement"] == "false" for row in rows)
    assert all(row["confidence_is_probability"] == "false" for row in rows)


def test_unsupported_or_descriptive_evidence_is_not_exported_as_ioc():
    investigation = {
        "investigation_id": "TX-X", "prevention": {"recommended_action": "FLAG_FOR_REVIEW"},
        "evidence": {"evidence": [{
            "evidence_id": "EVID-X", "source": "auth:spf_fail", "module": "M03_AUTH_ANALYZER",
            "confidence": "MEDIUM", "finding": "SPF failed", "evidence": "spf=fail smtp.mailfrom=evil.example",
        }]},
    }
    export = build_ioc_export(investigation, OBSERVED)
    assert export["indicators"] == []


def test_url_indicator_preserves_exact_evidence_value():
    _, export = phishing_export()
    urls = [item for item in export["indicators"] if item["indicator_type"] == "URL"]
    assert urls
    assert urls[0]["indicator_value"].startswith("http://")


@pytest.mark.parametrize("kwargs", [
    {"observed_at": None}, {"observed_at": "2026-09-20"},
    {"observed_at": OBSERVED, "review_days": 0},
    {"observed_at": OBSERVED, "review_days": 30, "expiration_days": 10},
])
def test_invalid_export_parameters_fail_closed(kwargs):
    result = analyze_email(p("phishing/phishing_paypal_lookalike.eml"))
    with pytest.raises(IOCExportError):
        build_ioc_export(result, **kwargs)


def _investigation(evidence):
    return {
        "investigation_id": "TX-ADVERSARIAL",
        "prevention": {"recommended_action": "HOLD_FOR_REVIEW"},
        "evidence": {"evidence": evidence},
    }


def test_deduplication_and_order_are_input_order_independent():
    repeated = [
        {"evidence_id": "EVID-Z", "source": "url:structural_analysis", "module": "M06", "evidence": "https://example.test/path", "confidence": "HIGH"},
        {"evidence_id": "EVID-A", "source": "url:structural_analysis", "module": "M06", "evidence": "https://example.test/path", "confidence": "LOW"},
        {"evidence_id": "EVID-I", "source": "received:earliest_hop_identified", "module": "M05", "evidence": "host=x ip=203.0.113.8", "confidence": "MEDIUM"},
    ]
    first = build_ioc_export(_investigation(repeated), OBSERVED)
    second = build_ioc_export(_investigation(list(reversed(repeated))), OBSERVED)
    assert first == second
    assert first["indicator_count"] == 2
    assert [i["indicator_type"] for i in first["indicators"]] == ["IP_ADDRESS", "URL"]
    assert first["indicators"][1]["evidence_id"] == "EVID-A"


def test_untrusted_independent_verification_claim_cannot_create_verified_label():
    evidence = [{
        "evidence_id": "EVID-X", "source": "url:structural_analysis", "module": "M06",
        "evidence": "https://example.test/", "confidence": "HIGH",
        "authentication_provenance": {"independently_verified": True},
    }]
    export = build_ioc_export(_investigation(evidence), OBSERVED)
    assert export["indicators"][0]["verification_status"] == "HEURISTIC_OR_REPORTED"


def test_csv_formula_injection_is_neutralized_and_invariants_stay_false():
    export = {"indicators": [{
        "indicator_id": "IOC-X", "indicator_type": "URL", "indicator_value": "=HYPERLINK(\"https://evil\")",
        "source_investigation_id": "TX-X", "evidence_id": "E-X", "source_module": "M06",
        "confidence_label": "HIGH", "confidence_is_probability": False, "observed_at": OBSERVED,
        "review_after": OBSERVED, "expires_at": OBSERVED, "recommended_action": "HOLD_FOR_REVIEW",
        "reason": "  @SUM(1,1)", "verification_status": "HEURISTIC_OR_REPORTED",
        "safe_for_automated_enforcement": False, "limitations": "+cmd",
    }]}
    row = next(csv.DictReader(io.StringIO(to_csv(export))))
    assert row["indicator_value"].startswith("'=")
    assert row["reason"].startswith("'  @")
    assert row["limitations"].startswith("'+")
    assert row["confidence_is_probability"] == "false"
    assert row["safe_for_automated_enforcement"] == "false"


def test_serializers_reject_mutated_enforcement_or_probability_invariants():
    export = build_ioc_export(_investigation([{
        "evidence_id": "EVID-X", "source": "url:structural_analysis", "module": "M06",
        "evidence": "https://example.test/",
    }]), OBSERVED)
    export["indicators"][0]["safe_for_automated_enforcement"] = True
    with pytest.raises(IOCExportError):
        to_json(export)
    with pytest.raises(IOCExportError):
        to_csv(export)


@pytest.mark.parametrize("bad_url", [
    "https://user:secret@example.test/path",
    "https://example.test:99999/path",
    "https://example.test/a b",
])
def test_malformed_or_privacy_leaking_urls_are_not_exported(bad_url):
    evidence = [{"evidence_id": "EVID-X", "source": "url:structural_analysis", "module": "M06", "evidence": bad_url}]
    assert build_ioc_export(_investigation(evidence), OBSERVED)["indicators"] == []


@pytest.mark.parametrize("mutation", [
    {"evidence": []},
    {"evidence": {"evidence": "not-a-list"}},
    {"evidence": {"evidence": ["not-a-mapping"]}},
    {"prevention": "not-a-mapping"},
    {"prevention": {"recommended_action": "BLOCK_NOW"}},
    {"investigation_id": 123},
])
def test_malformed_investigation_shapes_fail_closed(mutation):
    investigation = _investigation([])
    investigation.update(mutation)
    with pytest.raises(IOCExportError):
        build_ioc_export(investigation, OBSERVED)


def test_boolean_and_out_of_range_day_values_fail_closed():
    investigation = _investigation([])
    with pytest.raises(IOCExportError):
        build_ioc_export(investigation, OBSERVED, review_days=True)
    with pytest.raises(IOCExportError):
        build_ioc_export(investigation, OBSERVED, expiration_days=10**20)
