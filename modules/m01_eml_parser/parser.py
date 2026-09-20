"""
M01 — EML Parser

Takes a raw .eml file (path, bytes, or string) and produces a clean,
normalized ParsedEmail structure. Never executes attachments, scripts,
or visits URLs. Treats all input as untrusted.
"""
import re
from email import message_from_bytes, policy
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.models import ParsedEmail
from core.config import (MAX_EML_SIZE_BYTES, MAX_ATTACHMENT_SIZE_BYTES,
                         MAX_ATTACHMENTS_PER_EMAIL, MAX_URLS_PER_EMAIL,
                         MAX_RECEIVED_HOPS)
from core.utils import get_logger, sanitize_filename, sha256_bytes

logger = get_logger("m01_eml_parser")

MAX_SIZE_BYTES = MAX_EML_SIZE_BYTES  # backwards-compatible public name

URL_RE = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""",
)


class _HTMLTextExtractor(HTMLParser):
    """Converts HTML body to safe plain text. Never executes scripts/styles.
    Also collects link/src URLs found in attributes (never followed)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._parts: List[str] = []
        self._skip_depth = 0
        self._skip_tags = {"script", "style"}
        self.link_urls: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            self._skip_depth += 1
        if tag in ("br", "p", "div", "tr", "li"):
            self._parts.append("\n")
        for attr_name, attr_val in attrs:
            if attr_name in ("href", "src") and attr_val:
                self.link_urls.append(attr_val)

    def handle_endtag(self, tag):
        if tag in self._skip_tags and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _html_to_text_and_links(html: str):
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:  # malformed HTML must never crash the pipeline
        logger.warning(f"HTML parse warning: {e}")
    return parser.get_text(), parser.link_urls


def _extract_urls(*texts: str) -> List[str]:
    found: List[str] = []
    seen = set()
    for text in texts:
        if not text:
            continue
        for match in URL_RE.findall(text):
            url = match.rstrip(".,;:!?)")
            if url not in seen:
                seen.add(url)
                found.append(url)
    return found


def _addr_list(msg, header_name: str) -> List[str]:
    raw = msg.get_all(header_name, [])
    addrs = getaddresses(raw)
    return [addr for _, addr in addrs if addr]


def _single_addr(msg, header_name: str) -> Optional[str]:
    raw = msg.get(header_name)
    if not raw:
        return None
    addrs = getaddresses([raw])
    if addrs and addrs[0][1]:
        return addrs[0][1]
    return raw.strip()


def _safe_get_payload(part) -> bytes:
    try:
        payload = part.get_payload(decode=True)
        return payload if payload is not None else b""
    except Exception:
        return b""


def parse_eml(
    source: Union[str, bytes],
    source_filename: Optional[str] = None,
) -> ParsedEmail:
    """
    Parse a .eml file into a normalized ParsedEmail structure.

    `source` may be:
      - a filesystem path (str) to a .eml file
      - raw bytes of an .eml message
    """
    warnings: List[str] = []

    # ---- Load raw bytes ----
    if isinstance(source, (bytes, bytearray)):
        raw_bytes = bytes(source)
    else:
        p = Path(source)
        if not p.exists():
            raise FileNotFoundError(f"EML file not found: {source}")
        if p.stat().st_size > MAX_SIZE_BYTES:
            raise ValueError(f"EML file exceeds size limit ({MAX_SIZE_BYTES} bytes)")
        raw_bytes = p.read_bytes()
        if source_filename is None:
            source_filename = sanitize_filename(p.name)

    if len(raw_bytes) > MAX_EML_SIZE_BYTES:
        raise ValueError(f"EML input exceeds size limit ({MAX_EML_SIZE_BYTES} bytes)")

    if len(raw_bytes) == 0:
        warnings.append("Empty file: zero bytes")

    file_hash = sha256_bytes(raw_bytes)

    # ---- Parse with the modern email policy (handles encodings robustly) ----
    try:
        msg = message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as e:
        warnings.append(f"Primary parse failed ({e}); attempting compat parse")
        try:
            msg = message_from_bytes(raw_bytes, policy=policy.compat32)
        except Exception as e2:
            # Fully malformed: return a minimal structure rather than crashing
            warnings.append(f"Fallback parse also failed: {e2}")
            return ParsedEmail(
                from_=None, to=[], cc=[], subject=None, date=None,
                reply_to=None, return_path=None, message_id=None,
                received=[], authentication_results=[],
                body_plain="", body_html_text="", urls=[], attachments=[],
                raw_headers={}, file_sha256=file_hash,
                parse_warnings=warnings, source_filename=source_filename,
            )

    # ---- Headers ----
    from_ = _single_addr(msg, "From")
    to = _addr_list(msg, "To")
    cc = _addr_list(msg, "Cc")
    subject = msg.get("Subject")
    date = msg.get("Date")
    reply_to = _single_addr(msg, "Reply-To")
    return_path = _single_addr(msg, "Return-Path")
    message_id = msg.get("Message-ID")
    all_received = [str(h) for h in msg.get_all("Received", [])]
    received = all_received[:MAX_RECEIVED_HOPS]
    if len(all_received) > MAX_RECEIVED_HOPS:
        warnings.append(f"Received headers truncated to {MAX_RECEIVED_HOPS} of {len(all_received)}")
    auth_results = [str(h) for h in msg.get_all("Authentication-Results", [])]

    if from_ is None:
        warnings.append("Missing From header")
    if message_id is None:
        warnings.append("Missing Message-ID header")
    if date is None:
        warnings.append("Missing Date header")

    raw_headers: Dict[str, Any] = {}
    for key in msg.keys():
        values = msg.get_all(key, [])
        raw_headers[key] = [str(v) for v in values]

    # ---- Body extraction (plain + HTML→text) ----
    body_plain_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()

        if filename or disposition == "attachment":
            if len(attachments) >= MAX_ATTACHMENTS_PER_EMAIL:
                if not any(w.startswith("Attachment count truncated") for w in warnings):
                    warnings.append(f"Attachment count truncated to {MAX_ATTACHMENTS_PER_EMAIL}")
                continue
            payload = _safe_get_payload(part)
            if len(payload) > MAX_ATTACHMENT_SIZE_BYTES:
                warnings.append(f"Attachment {sanitize_filename(filename or 'unnamed_attachment')} exceeds metadata hashing limit; hash omitted")
                payload_hash = ""
            else:
                payload_hash = sha256_bytes(payload) if payload else ""
            attachments.append({
                "filename": sanitize_filename(filename or "unnamed_attachment"),
                "content_type": content_type,
                "size": len(payload),
                "sha256": payload_hash,
            })
            continue

        if content_type == "text/plain":
            payload = _safe_get_payload(part)
            try:
                charset = part.get_content_charset() or "utf-8"
                body_plain_parts.append(payload.decode(charset, errors="replace"))
            except Exception as e:
                warnings.append(f"Failed decoding text/plain part: {e}")
        elif content_type == "text/html":
            payload = _safe_get_payload(part)
            try:
                charset = part.get_content_charset() or "utf-8"
                html_str = payload.decode(charset, errors="replace")
                body_html_parts.append(html_str)
            except Exception as e:
                warnings.append(f"Failed decoding text/html part: {e}")

    body_plain = "\n".join(body_plain_parts).strip()
    html_texts = []
    html_link_urls: List[str] = []
    for h in body_html_parts:
        text, links = _html_to_text_and_links(h)
        html_texts.append(text)
        html_link_urls.extend(links)
    body_html_text = "\n".join(html_texts).strip()

    if not body_plain and not body_html_text:
        warnings.append("No text or HTML body content found")

    all_urls = _extract_urls(body_plain, body_html_text, "\n".join(html_link_urls))
    urls = all_urls[:MAX_URLS_PER_EMAIL]
    if len(all_urls) > MAX_URLS_PER_EMAIL:
        warnings.append(f"URL list truncated to {MAX_URLS_PER_EMAIL} of {len(all_urls)}")

    return ParsedEmail(
        from_=from_,
        to=to,
        cc=cc,
        subject=str(subject) if subject else None,
        date=str(date) if date else None,
        reply_to=reply_to,
        return_path=return_path,
        message_id=str(message_id) if message_id else None,
        received=received,
        authentication_results=auth_results,
        body_plain=body_plain,
        body_html_text=body_html_text,
        urls=urls,
        attachments=attachments,
        raw_headers=raw_headers,
        file_sha256=file_hash,
        parse_warnings=warnings,
        source_filename=source_filename,
    )
