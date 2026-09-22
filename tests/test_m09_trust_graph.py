from modules.m09_threat_graph.engine import build_sender_trust_graph

def test_unknown_sender_is_not_malicious_without_sensitive_signal():
    result = build_sender_trust_graph([], "new@example.com", False)
    assert result["findings"] == []

def test_first_seen_sensitive_request_is_cited_medium_signal():
    result = build_sender_trust_graph([], "new@example.com", True)
    assert result["findings"][0]["source"] == "trust:first_seen_sensitive_request"
    assert result["findings"][0]["severity"] == "MEDIUM"

def test_explicit_legitimate_feedback_suppresses_first_seen_signal():
    records=[{"feedback_id":"F1", "decision_type":"TRUSTED_SENDER", "details":{"sender":"known@example.com"}}]
    result=build_sender_trust_graph(records,"known@example.com",True)
    assert result["findings"] == []
    assert result["summary"]["confirmed_legitimate"] == 1
