import json
from pathlib import Path
import pytest
from modules.m19_audit_chain.engine import append_event, verify_chain
from modules.m20_case_store.store import CaseStore
from modules.m21_folder_ingest.watcher import ingest_once
DATA=Path(__file__).parents[1]/"test_data"
def fake(i, sha, domain, host):
 return {"investigation_id":i,"file":f"{i}.eml","file_sha256":sha,"identity":{"from_domain":domain,"reply_to_domain":domain,"display_name":"same"},"url_analysis":{"urls":[{"host":host}]},"email_summary":{"subject":"x"}}
def test_audit_chain_detects_tampering(tmp_path):
 p=tmp_path/"audit.jsonl"; a=append_event(str(p),actor="alice",action="ANALYZE_EMAIL",investigation_id="TX-1",input_sha256="a"*64); b=append_event(str(p),actor="bob",action="EXPORT_CASE",investigation_id="TX-1",input_sha256="a"*64)
 assert b["previous_hash"]==a["entry_hash"] and verify_chain(str(p))["valid"]
 rows=p.read_text().splitlines(); rows[0]=rows[0].replace("alice","mallory"); p.write_text("\n".join(rows)+"\n")
 assert not verify_chain(str(p))["valid"]
 with pytest.raises(ValueError): append_event(str(p),actor="x",action="X",investigation_id="TX-1",input_sha256="a"*64)
def test_store_persists_and_correlates_across_separate_adds(tmp_path):
 s=CaseStore(str(tmp_path/"cases.db")); assert s.add(fake("TX-1","1"*64,"evil.test","x.test")); assert s.add(fake("TX-2","2"*64,"evil.test","x.test")); assert not s.add(fake("TX-2","2"*64,"evil.test","x.test")); assert len(CaseStore(str(tmp_path/"cases.db")).list())==2; assert CaseStore(str(tmp_path/"cases.db")).correlate()["campaigns"][0]["related_email_count"]==2
def test_watched_folder_ingests_once_and_records_audit(tmp_path, monkeypatch):
 import modules.m21_folder_ingest.watcher as w
 inbox=tmp_path/"inbox"; inbox.mkdir(); src=DATA/"phishing"/"phishing_paypal_lookalike.eml"; (inbox/src.name).write_bytes(src.read_bytes())
 monkeypatch.setattr(w,"save_case",lambda result:{"case_dir":str(tmp_path/result["investigation_id"])})
 done=set(); first=ingest_once(str(inbox),db_path=str(tmp_path/"cases.db"),audit_path=str(tmp_path/"audit.jsonl"),processed=done); second=ingest_once(str(inbox),db_path=str(tmp_path/"cases.db"),audit_path=str(tmp_path/"audit.jsonl"),processed=done)
 assert len(first)==1 and second==[]; assert CaseStore(str(tmp_path/"cases.db")).list()[0]["risk"]["score"]==77; assert verify_chain(str(tmp_path/"audit.jsonl"))["valid"]
