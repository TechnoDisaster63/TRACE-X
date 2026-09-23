#!/usr/bin/env python3
"""TRACE-X offline SIH demo interface.

Binds to loopback only, has no external requests, and delegates all analysis and
case publication to the existing deterministic pipeline.
"""
from __future__ import annotations

import argparse
import cgi
import io
import json
import re
import os
import stat
import tempfile
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from core.pipeline import analyze_email, save_case, verify_case
from modules.m19_audit_chain.engine import append_event
from modules.m20_case_store.store import CaseStore

ROOT = Path(__file__).resolve().parent
SCENARIO_ROOT = ROOT / "demo_scenarios"
MAX_UPLOAD = 25 * 1024 * 1024
INVESTIGATION_ID = re.compile(r"^TX-[0-9]{6}$")


def _scenario_index() -> list[dict]:
    with (SCENARIO_ROOT / "index.json").open(encoding="utf-8") as stream:
        data = json.load(stream)
    for item in data:
        p = (ROOT / item["path"]).resolve()
        if ROOT not in p.parents or p.suffix.lower() != ".eml" or not p.is_file():
            raise ValueError(f"Unsafe or missing demo scenario: {item['path']}")
    return data


def _view(result: dict, package: dict, verification: dict) -> dict:
    evidence = []
    for item in result["evidence"]["evidence"]:
        evidence.append({
            "id": item["evidence_id"], "finding": item["finding"],
            "detail": item["evidence"], "severity": item["severity"],
            "observation_status": item.get("observation_status"),
            "source_reliability": item.get("source_reliability"),
            "analytic_confidence": item.get("analytic_confidence"),
            "origins": item.get("supporting_origins", []),
            "authentication_provenance": item.get("authentication_provenance"),
        })
    prevention = result["prevention"]
    return {
        "investigation_id": result["investigation_id"],
        "file": result["file"], "file_sha256": result["file_sha256"],
        "email_summary": result["email_summary"],
        "risk": result["risk"],
        "threat": result["threat_graph"],
        "evidence": evidence,
        "contradictions": result["evidence"]["provenance_graph"]["contradictions"],
        "graph_hash": result["evidence"]["provenance_graph"]["graph_hash"],
        "geo_infrastructure": {
            "database": result["geo_infrastructure"]["database"],
            "database_available": result["geo_infrastructure"]["database_available"],
            "hop_intelligence": result["geo_infrastructure"]["hop_intelligence"],
            "summary": result["geo_infrastructure"]["summary"],
            "capabilities": result["geo_infrastructure"]["capabilities"],
            "limitations": result["geo_infrastructure"]["limitations"],
        },
        "ml_phishing_signal": {
            "available": result["ml_phishing_signal"]["available"],
            "status": result["ml_phishing_signal"]["status"],
            "model_version": result["ml_phishing_signal"]["model_version"],
            "phishing_probability": result["ml_phishing_signal"]["phishing_probability"],
            "top_contributing_tokens": result["ml_phishing_signal"]["top_contributing_tokens"],
            "unavailable_reason": result["ml_phishing_signal"].get("unavailable_reason"),
            "advisory_only": result["ml_phishing_signal"]["advisory_only"],
            "executable": result["ml_phishing_signal"]["executable"],
            "limitations": result["ml_phishing_signal"].get("limitations", []),
        },
        "recommendation": prevention,
        "case_package": {
            "case_dir": package["case_dir"],
            "artifacts": {key: os.path.basename(value) for key, value in package.items() if key != "case_dir"},
            "verification": verification,
            "export_url": f"/api/export/{result['investigation_id']}",
            "export_format": "ZIP",
        },
        "boundaries": {
            "offline": True, "urls_visited": False, "attachments_executed": False,
            "campaign_scope": "BATCH_ONLY",
            "authentication": "REPORTED_HEADER_ANALYSIS; NOT INDEPENDENTLY VERIFIED",
            "recommendation_executable": False,
        },
    }


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "TRACE-X-Demo/1.0"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict | list) -> None:
        self._send(status, json.dumps(payload, separators=(",", ":"), default=str).encode(), "application/json; charset=utf-8")

    def _export(self, investigation_id: str) -> None:
        # Export only a complete, verified case generated by this local demo.
        if not INVESTIGATION_ID.fullmatch(investigation_id):
            self._json(404, {"error": "Export not found"}); return
        root = Path(os.environ.get("TRACE_X_OUTPUT_DIR", "output")).resolve()
        case_dir = (root / investigation_id).resolve()
        if case_dir.parent != root or not case_dir.is_dir():
            self._json(404, {"error": "Export not found"}); return
        verification = verify_case(str(case_dir))
        if not verification["valid"]:
            self._json(409, {"error": "Case integrity verification failed; export blocked."}); return
        expected = [f"{investigation_id}.json", f"{investigation_id}.txt", f"{investigation_id}.manifest.json"]
        if any(not (case_dir / name).is_file() for name in expected):
            self._json(409, {"error": "Case package is incomplete; export blocked."}); return
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name in expected:
                bundle.write(case_dir / name, arcname=name)
        body = archive.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{investigation_id}-case-package.zip"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, (ROOT / "demo_ui" / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self._send(200, (ROOT / "demo_ui" / "app.js").read_bytes(), "text/javascript; charset=utf-8")
        elif path == "/api/scenarios":
            self._json(200, _scenario_index())
        elif path.startswith("/api/export/"):
            self._export(path.removeprefix("/api/export/"))
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/analyze":
            self._json(404, {"error": "Not found"}); return
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_UPLOAD + 256 * 1024:
            self._json(413, {"error": "Input must be a .eml file no larger than 25 MB."}); return
        try:
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                    environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type", "")},
                                    keep_blank_values=True)
            scenario = form.getfirst("scenario", "").strip()
            trusted = [x.strip().lower() for x in form.getfirst("trusted_domains", "").split(",") if x.strip()]
            temp_path = None
            if scenario:
                match = next((x for x in _scenario_index() if x["id"] == scenario), None)
                if not match: raise ValueError("Unknown bundled scenario")
                input_path = str((ROOT / match["path"]).resolve())
            else:
                upload = form["eml"] if "eml" in form else None
                if upload is None or not getattr(upload, "filename", "") or not upload.filename.lower().endswith(".eml"):
                    raise ValueError("Choose a local .eml file or bundled scenario.")
                data = upload.file.read(MAX_UPLOAD + 1)
                if len(data) > MAX_UPLOAD: raise ValueError("Input exceeds the 25 MB safety limit.")
                fd, temp_path = tempfile.mkstemp(prefix="trace-x-demo-", suffix=".eml")
                try:
                    if hasattr(os, "fchmod"):
                        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
                    else:
                        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
                with os.fdopen(fd, "wb") as stream: stream.write(data)
                input_path = temp_path
            try:
                result = analyze_email(input_path, trusted_domains=trusted)
                package = save_case(result)
                CaseStore(os.environ.get("TRACE_X_CASE_DB", str(ROOT / "output" / "cases.sqlite3"))).add(result)
                append_event(os.environ.get("TRACE_X_AUDIT_LOG", str(ROOT / "output" / "audit-chain.jsonl")), actor=os.environ.get("TRACE_X_ACTOR", "LOCAL_CONSOLE"), action="ANALYZE_EMAIL", investigation_id=result["investigation_id"], input_sha256=result["file_sha256"], details={"source": "LOCAL_CONSOLE", "case_dir": package["case_dir"]})
                verification = verify_case(package["case_dir"])
                self._json(200, _view(result, package, verification))
            finally:
                if temp_path:
                    try: os.unlink(temp_path)
                    except FileNotFoundError: pass
        except (ValueError, KeyError, FileExistsError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self.log_error("analysis failed: %s", exc)
            self._json(500, {"error": "Analysis failed safely. No recommendation was executed."})

    def log_message(self, fmt: str, *args) -> None:
        print("TRACE-X demo:", fmt % args)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline TRACE-X SIH demo on loopback only")
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"TRACE-X offline demo: {url}", flush=True)
    print("Loopback-only. No URL visits, attachment execution, cloud service, API, or database.", flush=True)
    print("M17 geo intelligence and the M18 advisory ML signal run fully offline; neither changes the deterministic score.", flush=True)
    if not args.no_browser: webbrowser.open(url)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__":
    main()
