from pathlib import Path

from modules.m18_ml_phishing_signal.engine import (
    CLEANER_ID,
    DEFAULT_MODEL_PATH,
    analyze_ml_phishing_signal,
    clean_training_text,
)


def test_clear_phishing_sample_has_high_advisory_probability_and_explanations():
    text = """<html><body>Dear customer, your PayPal account security is limited.
    Click https://evil.invalid/verify now to update your account information and
    confirm your credit card or online banking access.</body></html>"""
    result = analyze_ml_phishing_signal(text)
    assert result["available"] is True
    assert result["phishing_probability"] > 0.80
    assert result["top_contributing_tokens"]
    assert any(item["token"] in {"account", "paypal", "security", "credit", "card", "banking"}
               for item in result["top_contributing_tokens"])
    assert len(result["findings"]) == 1
    assert result["findings"][0]["executable"] is False
    assert result["findings"][0]["severity"] == "INFO"


def test_clear_ham_sample_has_lower_advisory_probability():
    text = """Hi team, attached are the meeting notes and project schedule from
    yesterday. Please review the draft agenda before our Thursday discussion.
    Thanks for the helpful comments and see everyone at the office."""
    result = analyze_ml_phishing_signal(text)
    assert result["available"] is True
    assert result["phishing_probability"] < 0.50
    assert len(result["findings"]) == 1
    assert result["advisory_only"] is True


def test_missing_pickle_reports_unavailable_and_never_crashes(tmp_path):
    result = analyze_ml_phishing_signal("verify your account", str(tmp_path / "missing.pkl"))
    assert result["available"] is False
    assert result["phishing_probability"] is None
    assert result["status"] == "UNAVAILABLE"
    assert "pickle missing" in result["unavailable_reason"]
    assert result["findings"][0]["finding"] == "ML phishing-language signal unavailable"


def test_cleaner_parity_with_training_cell_order():
    raw = "<p>Hello&nbsp;world</p> https://example.test/a?b=1\n\t Next &amp; final"
    assert clean_training_text(raw) == "Hello world URL Next & final"
    assert CLEANER_ID == "strip_html+unescape+url_norm"


def test_bundled_model_is_present():
    assert Path(DEFAULT_MODEL_PATH).is_file()


def test_missing_sklearn_fallback_is_explicit(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "sklearn" or name.startswith("sklearn."):
            raise ModuleNotFoundError("blocked for graceful-degradation test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    result = analyze_ml_phishing_signal("verify account now")
    assert result["available"] is False
    assert result["status"] == "UNAVAILABLE"
    assert "ModuleNotFoundError" in result["unavailable_reason"]


def test_pipeline_normalizes_signal_without_affecting_rule_score(tmp_path):
    from core.pipeline import analyze_email

    eml = tmp_path / "sample.eml"
    eml.write_text(
        "From: billing@example.test\nTo: user@example.test\n"
        "Subject: Verify your PayPal account security\n"
        "Message-ID: <sample@example.test>\nDate: Tue, 22 Sep 2026 12:00:00 +0530\n"
        "Received: from mail.example.test (8.8.8.8) by mx.example.test\n\n"
        "Dear customer, click https://evil.invalid and update your account information.",
        encoding="utf-8",
    )
    result = analyze_email(str(eml))
    signal = result["ml_phishing_signal"]
    normalized = [item for item in result["evidence"]["evidence"]
                  if item["module"] == "M18_ML_PHISHING_SIGNAL"]
    assert signal["available"] is True
    assert len(signal["findings"]) == 1 and len(normalized) == 1
    assert normalized[0]["executable"] is False
    assert normalized[0]["severity"] == "INFO"
    assert all(factor["module"] != "M18_ML_PHISHING_SIGNAL"
               for factor in result["risk"]["risk_factors"])
