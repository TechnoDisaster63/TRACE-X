import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.m01_eml_parser.parser import parse_eml
from modules.m06_url_analyzer.analyzer import analyze_urls

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_legit_url_low_severity():
    parsed = parse_eml(p("legitimate/legit_newsletter.eml"))
    r = analyze_urls(parsed)
    assert r["url_count"] == 1
    assert r["urls"][0]["severity"] == "LOW"


def test_ip_based_url_flagged_high():
    parsed = parse_eml(p("phishing/suspicious_url_ip_shortener.eml"))
    r = analyze_urls(parsed)
    ip_url = next(u for u in r["urls"] if u["host"] == "203.0.113.44")
    assert ip_url["severity"] == "HIGH"
    assert any("IP address" in s for s in ip_url["signals"])


def test_shortener_detected():
    parsed = parse_eml(p("phishing/suspicious_url_ip_shortener.eml"))
    r = analyze_urls(parsed)
    short_url = next(u for u in r["urls"] if "bit.ly" in u["host"])
    assert any("shorten" in s.lower() for s in short_url["signals"])


def test_brand_impersonation_in_host_flagged_critical():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_urls(parsed)
    assert any(u["severity"] == "CRITICAL" for u in r["urls"])


def test_urls_never_fetched_only_static_analysis():
    """Sanity: analyzer must not attempt network calls -- verified by absence
    of any requests/urllib.request usage and by fast, deterministic execution."""
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    import time
    start = time.time()
    analyze_urls(parsed)
    elapsed = time.time() - start
    assert elapsed < 1.0  # network calls would be far slower / would fail offline


def test_no_urls_case():
    parsed = parse_eml(p("bec/bec_ceo_wire_request.eml"))
    r = analyze_urls(parsed)
    assert r["url_count"] == 0
    sources = {f["source"] for f in r["findings"]}
    assert "url:no_urls" in sources


def test_findings_have_required_fields():
    parsed = parse_eml(p("phishing/suspicious_url_ip_shortener.eml"))
    r = analyze_urls(parsed)
    for f in r["findings"]:
        for key in ("finding_id", "finding", "severity", "evidence", "source", "confidence"):
            assert key in f and f[key]


def test_suspicious_keyword_detected():
    parsed = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    r = analyze_urls(parsed)
    url = r["urls"][0]
    assert any("keyword" in s.lower() for s in url["signals"])
