"""M22 QR evidence worker. Runs as a bounded subprocess spawned by engine.py.

Self-contained on purpose: stdlib at module level, optional third-party runtime
(pypdf, pypdfium2, Pillow, numpy, OpenCV) imported lazily inside extract() so the
module imports cleanly on systems without the optional QR runtime.

Extraction only. Decoded payloads are recorded as evidence; they are never
visited, executed, or scored here. The Python-level socket denial below is
defence in depth for the offline guarantee, NOT a security sandbox: native
renderer code could bypass it. Hostile-file use still needs OS-level isolation
(container/seccomp/netns) on top of these bounds.
"""
import hashlib
import io
import json
import socket
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit

# Bounds precede any rasterization/decode. Values are the measured experiment
# bounds (see docs/specifications/QR_EVIDENCE.md).
MAX_PART_BYTES = 2 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_PAGES = 3
MAX_PARTS = 8
RENDER_SCALE = 1.5
RELEVANT_TYPES = ("image/png", "image/jpeg", "application/pdf")


def _deny_network(*_args, **_kwargs):
    raise RuntimeError("Network access prohibited in offline QR evidence worker")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _decode_image(im, evidence, part_index, part_hash, page, renderer):
    """Decode QR payloads from a PIL image; append evidence rows. Returns count."""
    import cv2
    import numpy as np

    arr = np.asarray(im)
    detector = cv2.QRCodeDetector()
    values = []
    ok, decoded, _points, _straight = detector.detectAndDecodeMulti(arr)
    if ok:
        values.extend(v for v in decoded if v)
    if not values:
        value, _points, _straight = detector.detectAndDecode(arr)
        if value:
            values = [value]
    count = 0
    for value in sorted(set(values)):
        split = urlsplit(value)
        is_url = split.scheme.lower() in ("http", "https") and bool(split.hostname)
        evidence.append({
            "payload": value,
            "is_http_url": is_url,
            "attachment_sha256": part_hash,
            "part_index": part_index,
            "page": page,
            "renderer": renderer,
            "decoder": "OpenCV " + cv2.__version__,
        })
        count += 1
    return count


def _pdf_images_pypdf(data, statuses, part_index):
    """Fast path: pull embedded images with pypdf (no rasterization).

    Returns (pages, encrypted) where pages is a list of (page_number, [PIL images])
    or None when pypdf cannot parse the file at all.
    """
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception:
        return None, False
    if reader.is_encrypted:
        try:
            unlocked = reader.decrypt("")
        except Exception:
            unlocked = None
        if not unlocked:
            return None, True
    if len(reader.pages) > MAX_PAGES:
        return "page_limit", False
    pages = []
    for page_number, page in enumerate(reader.pages, start=1):
        try:
            images = list(page.images)
        except Exception:
            images = []
        decoded_images = []
        for image in images:
            try:
                im = image.image  # PIL image
                if im.width * im.height > MAX_PIXELS:
                    raise ValueError("pixel_limit")
                decoded_images.append(im.convert("RGB"))
            except ValueError:
                raise
            except Exception:
                continue
        pages.append((page_number, decoded_images))
    return pages, False


def _pdf_render_pdfium(data, page_numbers, statuses, part_index):
    """Fallback: render pages with pypdfium2 (PDFium) and return PIL images.

    page_numbers is None when every page must be rendered (pypdf could not
    parse the file at all).
    """
    import pypdfium2 as pdfium

    try:
        doc = pdfium.PdfDocument(data)
    except pdfium.PdfiumError as exc:
        if getattr(exc, "err_code", None) == 4:
            return "encrypted"
        return "malformed"
    except Exception:
        return "malformed"
    if len(doc) > MAX_PAGES:
        return "page_limit"
    if page_numbers is None:
        page_numbers = list(range(1, len(doc) + 1))
    rendered = []
    for page_number in page_numbers:
        page = doc[page_number - 1]
        width, height = page.get_size()
        if width * RENDER_SCALE * height * RENDER_SCALE > MAX_PIXELS:
            return "pixel_limit"
        im = page.render(scale=RENDER_SCALE).to_pil().convert("RGB")
        rendered.append((page_number, im))
    return rendered


def extract(path):
    """Extract QR payloads from one .eml file. Returns evidence rows + statuses."""
    socket.socket = _deny_network
    socket.create_connection = _deny_network
    socket.getaddrinfo = _deny_network

    from PIL import Image

    raw = Path(path).read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    evidence = []
    statuses = []
    for part_index, part in enumerate(message.walk()):
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if content_type not in RELEVANT_TYPES:
            continue
        if len(statuses) >= MAX_PARTS:
            statuses.append({"status": "part_limit"})
            break
        data = part.get_payload(decode=True) or b""
        part_hash = _sha256(data)
        if len(data) > MAX_PART_BYTES:
            statuses.append({"part": part_index, "status": "byte_limit"})
            continue
        try:
            images = []  # list of (page_or_None, PIL image, renderer)
            if content_type == "application/pdf":
                pages, encrypted = _pdf_images_pypdf(data, statuses, part_index)
                if encrypted:
                    statuses.append({"part": part_index, "status": "encrypted"})
                    continue
                if pages == "page_limit":
                    statuses.append({"part": part_index, "status": "page_limit"})
                    continue
                if pages is None:
                    rendered = _pdf_render_pdfium(data, None, statuses, part_index)
                    if isinstance(rendered, str):
                        statuses.append({"part": part_index, "status": rendered})
                        continue
                else:
                    for page_number, embedded in pages:
                        for im in embedded:
                            images.append((page_number, im, "pypdf-embedded"))
                    # Pages with no decodable embedded image may hold a painted QR:
                    # render them with pdfium as the fallback path.
                    embedded_pages = {p for p, embedded in pages if embedded}
                    missing_pages = [p for p, embedded in pages if p not in embedded_pages]
                    if not missing_pages and not images:
                        missing_pages = [p for p, _ in pages]
                    if missing_pages:
                        rendered = _pdf_render_pdfium(data, missing_pages, statuses, part_index)
                        if isinstance(rendered, str):
                            statuses.append({"part": part_index, "status": rendered})
                            continue
                        for page_number, im in rendered:
                            images.append((page_number, im, "pdfium-render"))
            else:
                im = Image.open(io.BytesIO(data))
                if im.width * im.height > MAX_PIXELS:
                    raise ValueError("pixel_limit")
                im.load()
                images = [(None, im.convert("RGB"), "direct")]
            found = 0
            for page, im, renderer in images:
                found += _decode_image(im, evidence, part_index, part_hash, page, renderer)
            statuses.append({"part": part_index, "status": "decoded" if found else "not_decoded", "count": found})
        except Exception as exc:
            statuses.append({"part": part_index,
                             "status": "pixel_limit" if str(exc) == "pixel_limit" else "malformed"})
    versions = {}
    for module_name, package in (("pypdf", "pypdf"), ("pypdfium2", "pypdfium2"),
                                 ("PIL", "Pillow"), ("cv2", "OpenCV"), ("numpy", "numpy")):
        try:
            module = __import__(module_name)
            versions[package] = getattr(module, "__version__", "unknown")
        except Exception:
            versions[package] = "unavailable"
    return {"evidence": evidence, "statuses": statuses, "engines": versions}


if __name__ == "__main__":
    print(json.dumps(extract(sys.argv[1])))
