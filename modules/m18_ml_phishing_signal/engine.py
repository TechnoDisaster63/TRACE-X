"""M18 - optional, offline ML phishing-language evidence signal.

The model is advisory only. It neither decides whether an email is phishing nor
changes the deterministic rule score. Predictions are tied to per-email token
contributions and degrade to an explicit unavailable state when the optional ML
runtime or bundled artifact cannot be loaded.
"""
from __future__ import annotations

import html
import pickle
import re
from pathlib import Path
from typing import Optional

MODULE = "M18_ML_PHISHING_SIGNAL"
MODEL_VERSION = "tracex_ml_v2"
CLEANER_ID = "strip_html+unescape+url_norm"
DEFAULT_MODEL_PATH = Path(__file__).with_name("data") / "tracex_ml_v2.pkl"


def clean_training_text(text: str) -> str:
    """Reproduce the training cell's cleaner exactly, in the same order."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    text = re.sub(r"https?://\S+", " URL ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _finding(probability: Optional[float], top_tokens: list[dict], available: bool, reason: Optional[str] = None) -> dict:
    if not available:
        return {
            "finding_id": "ML-001",
            "finding": "ML phishing-language signal unavailable",
            "severity": "INFO",
            "evidence": f"status=UNAVAILABLE; reason={reason or 'optional ML runtime or model unavailable'}; no prediction produced",
            "source": "ml:phishing_language_signal",
            "confidence": "LOW",
            "category": "ML_ADVISORY",
            "module": MODULE,
            "executable": False,
        }
    token_text = ", ".join(f"{item['token']} ({item['contribution']:.6f})" for item in top_tokens) or "none"
    return {
        "finding_id": "ML-001",
        "finding": "Advisory ML phishing-language probability",
        "severity": "INFO",
        "evidence": f"calibrated_phishing_probability={probability:.6f}; top_contributing_tokens={token_text}; model={MODEL_VERSION}",
        "source": "ml:phishing_language_signal",
        "confidence": "LOW",
        "category": "ML_ADVISORY",
        "module": MODULE,
        "executable": False,
    }


def _positive_coefficients(model):
    """Average positive-class logistic coefficients across calibration folds."""
    rows = []
    for calibrated in getattr(model, "calibrated_classifiers_", ()):
        estimator = getattr(calibrated, "estimator", None)
        coef = getattr(estimator, "coef_", None)
        if coef is not None and len(coef):
            rows.append(coef[0])
    if not rows:
        estimator = getattr(model, "estimator", None) or getattr(model, "base_estimator", None)
        coef = getattr(estimator, "coef_", None)
        if coef is not None and len(coef):
            rows.append(coef[0])
    if not rows:
        raise ValueError("model exposes no logistic coefficients")
    if len(rows) == 1:
        return rows[0]
    return sum(rows) / len(rows)


def analyze_ml_phishing_signal(text: str, model_path: Optional[str] = None, top_n: int = 8) -> dict:
    """Return exactly one non-executable advisory evidence signal."""
    path = Path(model_path) if model_path is not None else DEFAULT_MODEL_PATH
    base = {
        "module": MODULE,
        "model_version": MODEL_VERSION,
        "model_path": path.name,
        "cleaner": CLEANER_ID,
        "available": False,
        "status": "UNAVAILABLE",
        "executable": False,
        "advisory_only": True,
        "phishing_probability": None,
        "top_contributing_tokens": [],
    }
    if not path.is_file():
        reason = "model pickle missing"
        base.update(unavailable_reason=reason, findings=[_finding(None, [], False, reason)])
        base["summary"] = {"signals": 1, "available": 0, "unavailable": 1}
        return base

    try:
        # scikit-learn is deliberately optional. Import first so a missing
        # runtime follows the same honest fallback as an unreadable artifact.
        import sklearn  # noqa: F401
        with path.open("rb") as stream:
            artifact = pickle.load(stream)
        vectorizer, model = artifact["vectorizer"], artifact["model"]
        if artifact.get("cleaner") != CLEANER_ID:
            raise ValueError("model cleaner metadata does not match inference cleaner")
        cleaned = clean_training_text(text)
        matrix = vectorizer.transform([cleaned])
        classes = list(model.classes_)
        positive_index = classes.index(1)
        probability = float(model.predict_proba(matrix)[0][positive_index])
        coefficients = _positive_coefficients(model)
        features = vectorizer.get_feature_names_out()
        row = matrix.getrow(0)
        contributions = []
        for feature_index, tfidf in zip(row.indices, row.data):
            contribution = float(tfidf * coefficients[feature_index])
            if contribution > 0:
                contributions.append({"token": str(features[feature_index]), "contribution": round(contribution, 8)})
        contributions.sort(key=lambda item: (-item["contribution"], item["token"]))
        contributions = contributions[: max(0, int(top_n))]
    except Exception as exc:
        reason = f"model unavailable ({type(exc).__name__})"
        base.update(unavailable_reason=reason, findings=[_finding(None, [], False, reason)])
        base["summary"] = {"signals": 1, "available": 0, "unavailable": 1}
        return base

    finding = _finding(probability, contributions, True)
    base.update(
        available=True,
        status="AVAILABLE",
        phishing_probability=round(probability, 8),
        top_contributing_tokens=contributions,
        findings=[finding],
        summary={"signals": 1, "available": 1, "unavailable": 0},
        limitations=[
            "Advisory language signal only; not a phishing verdict or automated action.",
            "Held-out metrics are test-set-only on historical public corpora and do not establish field accuracy.",
            "This signal complements and never overrides TRACE-X deterministic evidence and scoring.",
        ],
    )
    return base
