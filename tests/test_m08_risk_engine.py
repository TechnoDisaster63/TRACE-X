import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.m08_risk_engine.engine import compute_risk, SEVERITY_WEIGHTS

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _bundle(evidence_items):
    """Build a minimal, already-M07-shaped evidence bundle from raw
    (finding, severity, source, module, confidence) tuples."""
    evidence = []
    for i, (finding, severity, source, module, confidence) in enumerate(evidence_items, 1):
        evidence.append({
            "evidence_id": f"EVID-{i:04d}",
            "finding": finding,
            "severity": severity,
            "evidence": f"evidence-text-{i}",
            "source": source,
            "confidence": confidence,
            "category": "GENERAL",
            "module": module,
            "original_finding_id": f"F-{i}",
        })
    return {"evidence": evidence, "total_evidence_count": len(evidence)}


# ---------------------------------------------------------------------------
# Exact duplicate evidence (identical finding+evidence would already be
# deduped by M07 before reaching M08 - here we confirm M08 itself does not
# re-inflate if the *same* evidence_id / source appears twice, e.g. because
# an upstream bug let a duplicate slip through).
# ---------------------------------------------------------------------------

def test_exact_duplicate_source_does_not_double_full_weight():
    single = compute_risk(_bundle([
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
    ]))
    duplicated = compute_risk(_bundle([
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
    ]))
    # Second identical-source item must decay, not add a full second weight.
    assert duplicated["score"] < single["score"] * 2
    assert duplicated["score"] > single["score"]  # still contributes something


def test_duplicate_evidence_from_different_modules_decays():
    # Same underlying signal (reply-to mismatch) surfaced by both M02 and M04.
    risk = compute_risk(_bundle([
        ("Reply-To differs from From", "HIGH", "header:reply_to_vs_from", "M02_HEADER_FORENSICS", "HIGH"),
        ("Reply-To domain mismatch", "HIGH", "identity:reply_to_domain_mismatch", "M04_IDENTITY_ANALYZER", "HIGH"),
    ]))
    weights = {rf["source"]: rf["effective_weight"] for rf in risk["risk_factors"]}
    full = SEVERITY_WEIGHTS["HIGH"]
    assert max(weights.values()) == full
    assert min(weights.values()) < full


# ---------------------------------------------------------------------------
# Related-signal combinations
# ---------------------------------------------------------------------------

def test_replyto_plus_senderdomain_mismatch_correlated():
    risk = compute_risk(_bundle([
        ("Reply-To differs from From", "HIGH", "header:reply_to_vs_from", "M02_HEADER_FORENSICS", "HIGH"),
        ("Return-Path domain differs from From", "MEDIUM", "header:return_path_vs_from", "M02_HEADER_FORENSICS", "MEDIUM"),
    ]))
    groups = {rf["correlation_group"] for rf in risk["risk_factors"]}
    assert groups == {"IDENTITY_MISMATCH"}
    assert risk["score"] < SEVERITY_WEIGHTS["HIGH"] + SEVERITY_WEIGHTS["MEDIUM"]


def test_lookalike_plus_senderdomain_mismatch_independent_groups():
    risk = compute_risk(_bundle([
        ("Look-alike domain detected", "CRITICAL", "identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH"),
        ("Return-Path domain differs from From", "MEDIUM", "header:return_path_vs_from", "M02_HEADER_FORENSICS", "MEDIUM"),
    ]))
    # These are different correlation groups -> both should keep full weight.
    weights = {rf["source"]: rf["effective_weight"] for rf in risk["risk_factors"]}
    assert weights["identity:lookalike_domain"] == SEVERITY_WEIGHTS["CRITICAL"]
    assert weights["header:return_path_vs_from"] == SEVERITY_WEIGHTS["MEDIUM"]


def test_lookalike_plus_suspicious_url_independent():
    risk = compute_risk(_bundle([
        ("Look-alike domain detected", "CRITICAL", "identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH"),
        ("Suspicious URL structure", "HIGH", "url:structural_analysis", "M06_URL_ANALYZER", "MEDIUM"),
    ]))
    weights = {rf["source"]: rf["effective_weight"] for rf in risk["risk_factors"]}
    assert weights["identity:lookalike_domain"] == SEVERITY_WEIGHTS["CRITICAL"]
    assert weights["url:structural_analysis"] == SEVERITY_WEIGHTS["HIGH"]


def test_identity_plus_authentication_anomaly_independent():
    risk = compute_risk(_bundle([
        ("Look-alike domain detected", "CRITICAL", "identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH"),
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
    ]))
    assert risk["score"] == min(100, SEVERITY_WEIGHTS["CRITICAL"] + SEVERITY_WEIGHTS["HIGH"])
    assert risk["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_identity_url_and_auth_combined():
    risk = compute_risk(_bundle([
        ("Look-alike domain detected", "CRITICAL", "identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH"),
        ("Suspicious URL structure", "HIGH", "url:structural_analysis", "M06_URL_ANALYZER", "MEDIUM"),
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
    ]))
    assert len({rf["correlation_group"] for rf in risk["risk_factors"]}) == 3
    assert risk["risk_level"] in ("HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# Conflicting / low-confidence evidence
# ---------------------------------------------------------------------------

def test_conflicting_evidence_does_not_crash_and_still_scores():
    # e.g. SPF fail alongside DKIM/DMARC pass-equivalent (no finding emitted
    # for a pass, so only the fail surfaces) - engine must still produce a
    # coherent, bounded result.
    risk = compute_risk(_bundle([
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
    ]))
    assert 0 <= risk["score"] <= 100
    assert risk["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_low_confidence_evidence_still_contributes_but_labeled():
    risk = compute_risk(_bundle([
        ("Single Received hop observed", "LOW", "received:excessive_hops", "M05_RECEIVED_CHAIN", "LOW"),
    ]))
    assert risk["score"] == SEVERITY_WEIGHTS["LOW"]
    assert risk["confidence"] == "LOW"


# ---------------------------------------------------------------------------
# Determinism / bounds
# ---------------------------------------------------------------------------

def test_deterministic_repeated_execution():
    bundle = _bundle([
        ("Reply-To differs from From", "HIGH", "header:reply_to_vs_from", "M02_HEADER_FORENSICS", "HIGH"),
        ("Reply-To domain mismatch", "HIGH", "identity:reply_to_domain_mismatch", "M04_IDENTITY_ANALYZER", "HIGH"),
        ("Suspicious URL structure", "HIGH", "url:structural_analysis", "M06_URL_ANALYZER", "MEDIUM"),
    ])
    results = [compute_risk(bundle) for _ in range(5)]
    scores = {r["score"] for r in results}
    levels = {r["risk_level"] for r in results}
    assert len(scores) == 1
    assert len(levels) == 1


def test_score_never_below_zero():
    risk = compute_risk(_bundle([]))
    assert risk["score"] == 0
    assert risk["risk_level"] == "LOW"


def test_score_never_above_100():
    many_critical = [
        (f"Critical finding {i}", "CRITICAL", f"identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH")
        for i in range(20)
    ]
    risk = compute_risk(_bundle(many_critical))
    assert risk["score"] <= 100


def test_auth_pass_absence_does_not_override_suspicious_evidence():
    # No auth findings at all (i.e. auth "passed" -> no finding emitted),
    # but strong identity evidence is present. Risk must still reflect it.
    risk = compute_risk(_bundle([
        ("Look-alike domain detected", "CRITICAL", "identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH"),
    ]))
    # A single CRITICAL-severity finding must still register as meaningfully
    # risky (never LOW) even with no corroborating auth signal.
    assert risk["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert risk["score"] > 0


def test_single_auth_fail_does_not_automatically_reach_critical():
    risk = compute_risk(_bundle([
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
    ]))
    assert risk["risk_level"] != "CRITICAL"


def test_every_contribution_traceable_to_evidence_id():
    bundle = _bundle([
        ("SPF check failed", "HIGH", "auth:spf_fail", "M03_AUTH_ANALYZER", "HIGH"),
        ("Look-alike domain detected", "CRITICAL", "identity:lookalike_domain", "M04_IDENTITY_ANALYZER", "HIGH"),
    ])
    risk = compute_risk(bundle)
    valid_ids = {e["evidence_id"] for e in bundle["evidence"]}
    for rf in risk["risk_factors"]:
        assert rf["evidence_id"] in valid_ids
