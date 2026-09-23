"""Standard-library SQLite case index for durable local correlation."""
from __future__ import annotations
import json, sqlite3
from pathlib import Path
from modules.m09_threat_graph.engine import correlate_campaign
class CaseStore:
    def __init__(self, path: str): self.path = str(path)
    def _connect(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        db=sqlite3.connect(self.path); db.execute("PRAGMA journal_mode=WAL"); db.execute("CREATE TABLE IF NOT EXISTS cases (investigation_id TEXT PRIMARY KEY, file_sha256 TEXT NOT NULL, analyzed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, payload TEXT NOT NULL)"); return db
    def add(self, investigation: dict) -> bool:
        with self._connect() as db:
            cur=db.execute("INSERT OR IGNORE INTO cases(investigation_id,file_sha256,payload) VALUES(?,?,?)", (investigation["investigation_id"], investigation["file_sha256"], json.dumps(investigation, sort_keys=True, default=str)))
            return cur.rowcount == 1
    def list(self) -> list[dict]:
        with self._connect() as db: rows=db.execute("SELECT payload FROM cases ORDER BY analyzed_at, investigation_id").fetchall()
        return [json.loads(row[0]) for row in rows]
    def correlate(self) -> dict: return correlate_campaign(self.list())
