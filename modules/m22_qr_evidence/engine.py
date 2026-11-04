"""M22 - optional, opt-in, offline QR payload evidence from image/PDF attachments.

M22 recovers QR code payloads from PNG/JPEG images and PDF attachments as
advisory evidence. Extraction is not detection: a decoded payload is recorded,
never visited, never executed, and never scored (every finding is INFO, which
carries 0 points in the M08 rule engine). The module runs only when the caller
opts in (analyze_email(..., enable_qr_evidence=True) or CLI --qr-evidence);
default pipeline behaviour is unchanged.

The optional runtime (pypdf, pypdfium2, Pillow, numpy, OpenCV - see
requirements-qr.txt) is deliberately not a hard dependency. When it is missing,
M22 degrades to an explicit UNAVAILABLE finding instead of failing.

Hostile-file bounds (measured in the #39 experiments): the worker subprocess
gets a wall-clock timeout, and on POSIX also RLIMIT_CPU and RLIMIT_AS. These
limits bound runaway work but are NOT a security sandbox; the Python-level
socket denial in the worker is not either. Hostile-file production use still
needs OS-level isolation (container/seccomp/netns). See
docs/security/LIMITATIONS_AND_NON_GOALS.md.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

MODULE = "M22_QR_EVIDENCE"
WORKER_PATH = Path(__file__).with_name("worker.py")

# Measured experiment bounds (round 1 + round 2, issue #39). Keep in sync with
# worker.py; the engine owns the process-level guard values.
MAX_PART_BYTES = 2 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_PAGES = 3
MAX_PARTS = 8
WALL_TIMEOUT_SECONDS = 10
CPU_LIMIT_SECONDS = 8
ADDRESS_SPACE_LIMIT_BYTES = 1 * 1024 * 1024 * 1024

RUNTIME_COMPONENTS = ("cv2", "numpy", "PIL", "pypdf", "pypdfium2")

LIMITATIONS = [
    "Extraction is evidence recovery, not phishing detection; a decoded QR payload is not a verdict.",
    "Decoded URLs are recorded only. TRACE-X never visits them.",
    "The process bounds limit runaway CPU/memory/time but are not a security sandbox.",
    "The Python-level network denial can be bypassed by native renderer code; hostile-file use needs OS-level isolation.",
    "Very small QR images (around 38x38 px in the synthetic fixtures) are below the OpenCV detector limit and do not decode.",
    "Effectiveness on real mail is unproven until the M18 modern-dataset work (issue #38) lands.",
]


def _missing_runtime_components() -> List[str]:
    """Names of optional runtime packages that cannot be imported here."""
    missing = []
    for name in RUNTIME_COMPONENTS:
        try:
            if importlib.util.find_spec(name) is None:
                missing.append(name)
        except ImportError:
            missing.append(name)
    return missing


def _unavailable(reason: str) -> dict:
    result = _base()
    result.update(
        unavailable_reason=reason,
        findings=[{
            "finding_id": "QR-000",
            "finding": "QR evidence extraction unavailable",
            "severity": "INFO",
            "evidence": f"status=UNAVAILABLE; reason={reason}; no extraction performed",
            "source": "attachment:qr_evidence",
            "confidence": "LOW",
            "category": "QR_EVIDENCE",
            "module": MODULE,
            "executable": False,
        }],
    )
    result["summary"] = {"payloads_decoded": 0, "parts_examined": 0, "available": 0, "unavailable": 1}
    return result


def _base() -> dict:
    return {
        "module": MODULE,
        "available": False,
        "status": "UNAVAILABLE",
        "executable": False,
        "advisory_only": True,
        "offline": True,
        "limits": {
            "max_part_bytes": MAX_PART_BYTES,
            "max_pixels": MAX_PIXELS,
            "max_pages": MAX_PAGES,
            "max_parts": MAX_PARTS,
            "wall_timeout_seconds": WALL_TIMEOUT_SECONDS,
            "cpu_limit_seconds": CPU_LIMIT_SECONDS,
            "address_space_limit_bytes": ADDRESS_SPACE_LIMIT_BYTES,
        },
        "guard": None,
        "engines": {},
        "evidence": [],
        "extraction_statuses": [],
        "findings": [],
        "limitations": LIMITATIONS,
    }


def _posix_limits():  # pragma: no cover - exercised indirectly on POSIX
    import resource

    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS + 2))
        resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_LIMIT_BYTES,) * 2)

    return apply


def _finding(index: int, row: dict) -> dict:
    page = row.get("page")
    where = f"part_index={row['part_index']}" + (f"; page={page}" if page else "")
    return {
        "finding_id": f"QR-{index:03d}",
        "finding": "QR payload recovered from attachment (evidence only, not a verdict)",
        "severity": "INFO",
        "evidence": (
            f"payload={row['payload']!r}; {where}; attachment_sha256={row['attachment_sha256']}; "
            f"is_http_url={row['is_http_url']}; renderer={row['renderer']}; decoder={row['decoder']}; "
            f"URL recorded, never visited"
        ),
        "source": f"attachment:qr_payload[{row['part_index']}]",
        "confidence": "HIGH",
        "category": "QR_EVIDENCE",
        "module": MODULE,
        "executable": False,
    }


def analyze_qr_evidence(path: str, timeout_seconds: Optional[int] = None) -> dict:
    """Extract QR payloads from image/PDF attachments of one .eml, bounded.

    Returns an M18-style result mapping: advisory, non-executable, explicit
    about availability and per-part extraction status. Never raises for
    missing runtime, hostile input, or worker failure; every failure mode is a
    recorded status.
    """
    missing = _missing_runtime_components()
    if missing:
        return _unavailable(
            "optional QR runtime not installed (missing: "
            + ", ".join(missing)
            + "); see requirements-qr.txt"
        )

    timeout = int(timeout_seconds or WALL_TIMEOUT_SECONDS)
    preexec = None
    guard = "wall_timeout_only"
    if os.name == "posix":
        try:
            preexec = _posix_limits()
            guard = "wall_timeout+rlimit_cpu+rlimit_as"
        except Exception:
            preexec = None

    result = _base()
    result["guard"] = guard
    try:
        completed = subprocess.run(
            [sys.executable, str(WORKER_PATH), str(path)],
            capture_output=True, text=True, timeout=timeout,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired:
        result["extraction_statuses"] = [{"status": "timeout", "wall_timeout_seconds": timeout}]
        result["status"] = "TIMEOUT"
        result["summary"] = {"payloads_decoded": 0, "parts_examined": 0, "available": 1, "unavailable": 0}
        return result
    except Exception as exc:
        return _unavailable(f"worker could not start ({type(exc).__name__})")

    if completed.returncode != 0:
        result["extraction_statuses"] = [{
            "status": "worker_terminated",
            "returncode": completed.returncode,
            "stderr_tail": (completed.stderr or "")[-200:],
        }]
        result["status"] = "WORKER_TERMINATED"
        result["summary"] = {"payloads_decoded": 0, "parts_examined": 0, "available": 1, "unavailable": 0}
        return result

    try:
        payload = json.loads(completed.stdout)
    except ValueError:
        result["extraction_statuses"] = [{"status": "worker_error", "detail": "unparseable worker output"}]
        result["status"] = "WORKER_ERROR"
        result["summary"] = {"payloads_decoded": 0, "parts_examined": 0, "available": 1, "unavailable": 0}
        return result

    evidence = payload.get("evidence", [])
    statuses = payload.get("statuses", [])
    findings = [_finding(i + 1, row) for i, row in enumerate(evidence)]
    result.update(
        available=True,
        status="AVAILABLE",
        engines=payload.get("engines", {}),
        evidence=evidence,
        extraction_statuses=statuses,
        findings=findings,
        summary={
            "payloads_decoded": len(evidence),
            "parts_examined": sum(1 for s in statuses if s.get("part") is not None),
            "available": 1,
            "unavailable": 0,
        },
    )
    return result
