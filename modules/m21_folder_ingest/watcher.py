"""Polling watched-folder ingestion; local, bounded, and dependency-free."""
from __future__ import annotations
import time
from pathlib import Path
from core.pipeline import analyze_email, save_case
from modules.m19_audit_chain.engine import append_event
from modules.m20_case_store.store import CaseStore

def ingest_once(folder: str, *, db_path: str, audit_path: str, actor: str = "WATCHER", processed: set[str] | None = None) -> list[dict]:
    done=processed if processed is not None else set(); results=[]; store=CaseStore(db_path)
    for path in sorted(Path(folder).glob("*.eml")):
        marker=str(path.resolve())
        if marker in done: continue
        result=analyze_email(str(path)); package=save_case(result); store.add(result)
        append_event(audit_path, actor=actor, action="ANALYZE_EMAIL", investigation_id=result["investigation_id"], input_sha256=result["file_sha256"], details={"source":"WATCHED_FOLDER", "file":path.name, "case_dir":package["case_dir"]})
        done.add(marker); results.append(result)
    return results

def watch(folder: str, *, db_path: str, audit_path: str, actor: str = "WATCHER", interval: float = 2.0) -> None:
    done=set()
    while True:
        ingest_once(folder, db_path=db_path, audit_path=audit_path, actor=actor, processed=done)
        time.sleep(interval)
