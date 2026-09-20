import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from modules.m01_eml_parser.parser import parse_eml

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")


def p(rel):
    return os.path.join(DATA, rel)


def test_valid_email_basic_fields():
    r = parse_eml(p("legitimate/legit_newsletter.eml"))
    assert r.from_ == "news@acme-corp.example"
    assert r.subject == "Your October Newsletter"
    assert r.message_id == "<news-2026-10-05@acme-corp.example>"
    assert len(r.authentication_results) == 1
    assert "acme-corp.example/news" in r.urls[0]
    assert r.file_sha256 and len(r.file_sha256) == 64


def test_malformed_truncated_does_not_crash():
    r = parse_eml(p("malformed/malformed_truncated.eml"))
    assert isinstance(r.parse_warnings, list)


def test_empty_email():
    r = parse_eml(p("malformed/malformed_empty.eml"))
    assert "Empty file: zero bytes" in r.parse_warnings


def test_missing_headers_flagged():
    r = parse_eml(p("malformed/malformed_truncated.eml"))
    # Message-ID and Date are absent in this malformed sample
    assert "Missing Message-ID header" in r.parse_warnings
    assert "Missing Date header" in r.parse_warnings


def test_multipart_html_email_html_to_text():
    r = parse_eml(p("phishing/phishing_paypal_lookalike.eml"))
    assert "verify your account" in r.body_html_text.lower()
    assert "<a href" not in r.body_html_text.lower()
    assert any("paypa1-verify.com.secure-login.info" in u for u in r.urls)


def test_unicode_email_decodes_and_subject_decoded():
    r = parse_eml(p("edge_cases/unicode_encoded_headers.eml"))
    assert "café" in r.body_plain
    # MIME-encoded header should be decoded, not left as raw =?UTF-8?B?...
    assert r.subject is not None
    assert "=?UTF-8?" not in r.subject.replace(" ", "")


def test_encoded_headers_from_display_name():
    r = parse_eml(p("edge_cases/unicode_encoded_headers.eml"))
    assert r.from_ == "jose@example.com"


def test_multiple_recipients():
    r = parse_eml(p("edge_cases/multi_received_multi_recipient.eml"))
    assert len(r.to) == 3
    assert "bob@example.com" in r.to
    assert len(r.cc) == 1


def test_multiple_received_headers_preserved_in_order():
    r = parse_eml(p("edge_cases/multi_received_multi_recipient.eml"))
    assert len(r.received) == 3
    assert "mx1.example.com" in r.received[0]
    assert "relay.example.com" in r.received[2]


def test_attachment_metadata_extracted_and_not_executed():
    r = parse_eml(p("edge_cases/attachment_email.eml"))
    assert len(r.attachments) == 1
    att = r.attachments[0]
    assert att["filename"] == "policy.pdf"
    assert att["content_type"] == "application/pdf"
    assert att["size"] > 0
    assert len(att["sha256"]) == 64


def test_attachment_filename_sanitized():
    raw = (
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n"
        b"Message-ID: <x@example.com>\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="../../etc/passwd"\r\n\r\n'
        b"data\r\n--B--\r\n"
    )
    r = parse_eml(raw, source_filename="test.eml")
    assert len(r.attachments) == 1
    assert ".." not in r.attachments[0]["filename"]
    assert "/" not in r.attachments[0]["filename"]


def test_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        parse_eml(p("does_not_exist.eml"))


def test_never_executes_html_script_tag():
    raw = (
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n"
        b"Message-ID: <x@example.com>\r\nContent-Type: text/html\r\n\r\n"
        b"<html><body><script>alert(1)</script><p>Hello</p></body></html>"
    )
    r = parse_eml(raw, source_filename="script.eml")
    assert "alert(1)" not in r.body_html_text
    assert "Hello" in r.body_html_text


def test_urls_extracted_from_plain_and_html():
    r = parse_eml(p("phishing/suspicious_url_ip_shortener.eml"))
    assert any("203.0.113.44" in u for u in r.urls)
    assert any("bit.ly" in u for u in r.urls)


def test_bytes_input_supported():
    with open(p("legitimate/legit_newsletter.eml"), "rb") as f:
        raw = f.read()
    r = parse_eml(raw, source_filename="legit.eml")
    assert r.from_ == "news@acme-corp.example"
