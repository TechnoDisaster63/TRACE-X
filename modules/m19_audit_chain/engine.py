"""Offline append-only, hash-chained investigation audit journal."""
from __future__ import annotations
import hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path
from core.utils import canonical_json_bytes, private_makedirs
GENESIS = "0" * 64

def _digest(entry: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(entry)).hexdigest()

def verify_chain(path: str) -> dict:
    previous, count, errors = GENESIS, 0, []
    journal = Path(path)
    if not journal.exists(): return {"valid": True, "entries": 0, "head_hash": GENESIS, "errors": []}
    for line_no, line in enumerate(journal.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip(): continue
        try: record = json.loads(line)
        except ValueError as exc:
            errors.append(f"line {line_no}: invalid JSON: {exc}"); break
        claimed = record.pop("entry_hash", None)
        if record.get("sequence") != count + 1: errors.append(f"line {line_no}: sequence mismatch")
        if record.get("previous_hash") != previous: errors.append(f"line {line_no}: previous hash mismatch")
        actual = _digest(record)
        if claimed != actual: errors.append(f"line {line_no}: entry hash mismatch")
        previous, count = claimed or actual, count + 1
    return {"valid": not errors, "entries": count, "head_hash": previous, "errors": errors}

def append_event(path: str, *, actor: str, action: str, investigation_id: str, input_sha256: str, details: dict | None = None, occurred_at: str | None = None) -> dict:
    state = verify_chain(path)
    if not state["valid"]: raise ValueError("Refusing to append to an invalid audit chain")
    journal = Path(path); private_makedirs(str(journal.parent))
    entry = {"sequence": state["entries"] + 1, "occurred_at_utc": occurred_at or datetime.now(timezone.utc).isoformat(), "actor": actor, "action": action, "investigation_id": investigation_id, "input_sha256": input_sha256, "details": details or {}, "previous_hash": state["head_hash"]}
    entry["entry_hash"] = _digest(entry)
    fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"); stream.flush(); os.fsync(stream.fileno())
    return entry
