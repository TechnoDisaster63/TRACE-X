import os

from core.pipeline import analyze_email
from modules.m11_prevention_recommendation.bec import assess_bec

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_bec_fixture_combines_content_and_forensic_categories():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    bec = result["prevention"]["bec_assessment"]
    categories = {item["category"] for item in bec["indicators"]}
    assert bec["status"] == "REVIEW_RECOMMENDED"
    assert "CONTENT" in categories
    assert "IDENTITY" in categories
    assert bec["evidence_ids"]
    assert bec["executable"] is False


def test_keywords_alone_are_insufficient_for_bec():
    parsed = {"subject": "Urgent invoice payment", "body_plain": "Please pay this invoice today."}
    bec = assess_bec(parsed, {"evidence": []}, {"threat_class": "UNKNOWN"})
    assert bec["status"] == "INSUFFICIENT_CORROBORATION"
    assert bec["recommended_safeguards"] == []
    assert "content indicator alone is insufficient" in " ".join(bec["counterfactuals"]).lower()


def test_identity_anomaly_without_bec_content_does_not_trigger_workflow():
    evidence = {"evidence": [{
        "evidence_id": "EVID-1", "source": "header:reply_to_vs_from"
    }]}
    bec = assess_bec({"subject": "Weekly update"}, evidence, {"threat_class": "UNKNOWN"})
    assert bec["status"] == "NOT_INDICATED"


def test_financial_request_adds_financial_approval_safeguard():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    safeguards = result["prevention"]["bec_assessment"]["recommended_safeguards"]
    assert any("financial approval" in item for item in safeguards)


def test_bec_indicators_do_not_copy_raw_message_text():
    secret = "unique-private-needle-123"
    parsed = {"subject": "Urgent wire payment", "body_plain": f"Send payment now {secret}"}
    evidence = {"evidence": [{
        "evidence_id": "EVID-1", "source": "identity:reply_to_domain_mismatch"
    }]}
    bec = assess_bec(parsed, evidence, {"threat_class": "BEC"})
    assert secret not in repr(bec)


def test_bec_explanation_does_not_claim_malicious_intent():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    text = result["prevention"]["bec_assessment"]["explanation"].lower()
    assert "malicious intent is not established" in text


def test_legitimate_fixture_is_not_indicated():
    result = analyze_email(p("legitimate/legit_newsletter.eml"), trusted_domains=["acme-corp.example"])
    assert result["prevention"]["bec_assessment"]["status"] == "NOT_INDICATED"


def test_bec_counterfactuals_flow_to_recommendation():
    result = analyze_email(p("bec/bec_ceo_wire_request.eml"))
    rec = result["prevention"]
    assert all(item in rec["counterfactuals"] for item in rec["bec_assessment"]["counterfactuals"])
