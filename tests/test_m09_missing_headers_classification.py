"""Missing delivery headers must not, on their own, classify mail as INFRASTRUCTURE_ABUSE.

Found by the Enron false-alarm check (docs/evaluation/ENRON_FALSE_POSITIVE.md): the CMU
release strips Received/Authentication-Results headers, and every legitimate message was
classified INFRASTRUCTURE_ABUSE purely on those missing-header findings."""
from core.pipeline import analyze_email
from modules.m09_threat_graph import engine as tg

HEADERLESS_LEGIT = (
    "Message-ID: <25852139.1075853981594.JavaMail.evans@thyme>\n"
    "Date: Wed, 27 Sep 2000 00:26:00 -0700 (PDT)\n"
    "From: silver.breaux@example.com\n"
    "To: daren.farmer@example.com\n"
    "Subject: Accum.\n"
    "Mime-Version: 1.0\n"
    "Content-Type: text/plain; charset=us-ascii\n"
    "\n"
    "Daren, the accumulated volumes for September are attached to the usual sheet.\n"
)


def test_headerless_legitimate_message_is_not_infrastructure_abuse(tmp_path):
    path = tmp_path / "headerless_legit.eml"
    path.write_text(HEADERLESS_LEGIT)
    result = analyze_email(str(path))
    graph = result["threat_graph"]
    assert graph["threat_class"] != "INFRASTRUCTURE_ABUSE"
    assert "INFRASTRUCTURE_ABUSE" not in {p["pattern_id"] for p in graph["threat_patterns"]}


def test_missing_received_sources_map_to_missing_signal_not_anomaly():
    for source in ("header:received_missing", "received:no_hops"):
        assert tg.SOURCE_TO_SIGNAL[source] == "RECEIVED_CHAIN_MISSING"


def test_missing_chain_plus_header_anomaly_does_not_match_infrastructure_abuse():
    matched = {p["pattern_id"] for p in tg._detect_patterns({"RECEIVED_CHAIN_MISSING", "HEADER_ANOMALY"})}
    assert "INFRASTRUCTURE_ABUSE" not in matched


def test_real_chain_anomaly_plus_header_anomaly_still_matches_infrastructure_abuse():
    matched = {p["pattern_id"] for p in tg._detect_patterns({"RECEIVED_CHAIN_ANOMALY", "HEADER_ANOMALY"})}
    assert "INFRASTRUCTURE_ABUSE" in matched
