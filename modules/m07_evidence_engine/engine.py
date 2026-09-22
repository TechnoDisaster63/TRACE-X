"""M07 - deterministic evidence normalization and compact provenance graph."""
import re
from typing import Dict, List
from core.config import (EVIDENCE_SCHEMA_VERSION, MAX_PROVENANCE_EDGES,
                         MAX_PROVENANCE_NODES, PROVENANCE_RULESET_VERSION)
from core.utils import canonical_json_bytes, severity_rank, sha256_bytes, stable_object_id

MODULE_SOURCE_LABEL = {
    "header_forensics": "M02_HEADER_FORENSICS", "authentication": "M03_AUTH_ANALYZER",
    "identity": "M04_IDENTITY_ANALYZER", "received_chain": "M05_RECEIVED_CHAIN",
    "url_analysis": "M06_URL_ANALYZER", "geo_infra": "M17_GEO_INFRA_INTEL",
    "trust_graph": "M09_TRUST_GRAPH",
}

def reset_counter():
    """Compatibility no-op: identifiers are now content-derived and analysis-local."""

def _status(module_key):
    return "REPORTED" if module_key == "authentication" else "OBSERVED"

def _reliability(module_key, auth_prov=None):
    if module_key == "authentication":
        return "MEDIUM" if auth_prov and auth_prov["trusted_source"] else "LOW"
    return "MEDIUM"

def _polarity(text):
    t = text.lower()
    negative = ("fail", "mismatch", "missing", "suspicious", "invalid", "anomal", "not ", "none")
    positive = ("pass", "match", "valid", "aligned", "trusted")
    if any(x in t for x in negative): return "NEGATIVE"
    if any(x in t for x in positive): return "POSITIVE"
    return "ASSERTED"

def _claim_key(item):
    source = re.sub(r"[:/][0-9]+$", "", item.get("source", "unknown"))
    return f"{item.get('category','GENERAL')}:{source}"

def _locator(raw, module_key, occurrence):
    source = str(raw.get("source", "finding"))
    kind, _, path = source.partition(":")
    return {"artifact_id": "input-eml", "kind": kind or module_key,
            "path": path or source, "occurrence": int(raw.get("source_occurrence", 0)),
            "byte_start": None, "byte_end": None}

def build_evidence_bundle(header_result, auth_result, identity_result, received_result, url_result, geo_result=None, extra_results=None):
    module_results = {"header_forensics": header_result, "authentication": auth_result,
                      "identity": identity_result, "received_chain": received_result,
                      "url_analysis": url_result}
    if geo_result is not None:
        module_results["geo_infra"] = geo_result
    for key, value in (extra_results or {}).items():
        module_results[key] = value
    grouped = {}
    for module_key, result in module_results.items():
        for occurrence, raw in enumerate(result.get("findings", [])):
            key = (raw["finding"], raw["evidence"])
            origin = {"module": MODULE_SOURCE_LABEL[module_key],
                      "original_finding_id": raw["finding_id"],
                      "source_locator": _locator(raw, module_key, occurrence),
                      "raw_digest": sha256_bytes(str(raw.get("evidence", "")).encode("utf-8")),
                      "transforms": ["M07_NORMALIZE_V1"]}
            if key not in grouped:
                grouped[key] = {"raw": raw, "module_key": module_key, "origins": [origin]}
            else:
                grouped[key]["origins"].append(origin)
    items = []
    for key in sorted(grouped, key=lambda k: canonical_json_bytes(k)):
        entry, raw, module_key = grouped[key], grouped[key]["raw"], grouped[key]["module_key"]
        auth_prov = None
        if module_key == "authentication":
            mechanism = next((m for m in ("spf","dkim","dmarc") if raw.get("source", "").startswith(f"auth:{m}")), None)
            mr = auth_result.get(mechanism, {}) if mechanism else {}
            trusted = bool(mr.get("trusted_source", False))
            auth_prov = {"mechanism": mechanism, "authserv_id": mr.get("authserv_id"),
                         "trusted_source": trusted,
                         "verification_state": "REPORTED_TRUSTED_SOURCE" if trusted else "REPORTED_UNVERIFIED",
                         "independently_verified": False}
        entry["origins"].sort(key=lambda o: canonical_json_bytes(o))
        locator_list = [o["source_locator"] for o in entry["origins"]]
        identity = {"finding": raw["finding"], "evidence": raw["evidence"],
                    "category": raw.get("category", "GENERAL"), "locators": locator_list}
        node_id = stable_object_id("EV", identity)
        item = {"evidence_id": node_id, "legacy_evidence_id": f"EVID-{len(items)+1:04d}",
                "finding": raw["finding"], "severity": raw["severity"], "evidence": raw["evidence"],
                "source": raw["source"], "confidence": raw["confidence"],
                "category": raw.get("category", "GENERAL"),
                "module": entry["origins"][0]["module"],
                "original_finding_id": entry["origins"][0]["original_finding_id"],
                "supporting_origins": entry["origins"],
                "supporting_finding_ids": [o["original_finding_id"] for o in entry["origins"]],
                "observation_status": _status(module_key),
                "source_reliability": _reliability(module_key, auth_prov),
                "analytic_confidence": raw["confidence"],
                "confidence_rationale": "Producer confidence retained; source reliability is assessed separately.",
                "claim_key": _claim_key(raw), "claim_polarity": _polarity(raw["finding"] + " " + raw["evidence"])}
        if auth_prov:
            item["authentication_provenance"] = auth_prov
            item["automated_prevention_eligible"] = auth_prov["trusted_source"]
        items.append(item)
    items.sort(key=lambda e: (-severity_rank(e["severity"]), e["evidence_id"]))
    nodes = [{"node_id": e["evidence_id"], "finding": e["finding"], "category": e["category"],
              "observation_status": e["observation_status"], "source_reliability": e["source_reliability"],
              "analytic_confidence": e["analytic_confidence"], "severity": e["severity"],
              "locators": [o["source_locator"] for o in e["supporting_origins"]],
              "supporting_finding_ids": e["supporting_finding_ids"],
              "rationale": e["confidence_rationale"]} for e in items]
    edges = []
    for e in items:
        for origin in e["supporting_origins"]:
            oid = stable_object_id("OR", origin)
            edges.append({"edge_id": stable_object_id("PE", [oid,e["evidence_id"],"ORIGIN"]),
                          "source_node_id": oid, "target_node_id": e["evidence_id"],
                          "edge_type": "ORIGIN", "rationale": "Finding was normalized from this preserved origin."})
    contradictions = []
    by_claim = {}
    for e in items: by_claim.setdefault(e["claim_key"], []).append(e)
    for claim, claim_items in sorted(by_claim.items()):
        polarities = {e["claim_polarity"] for e in claim_items}
        if "POSITIVE" in polarities and "NEGATIVE" in polarities:
            ids = sorted(e["evidence_id"] for e in claim_items)
            cid = stable_object_id("CON", [claim, ids])
            contradictions.append({"contradiction_id": cid, "claim_key": claim, "node_ids": ids,
                                   "status": "UNRESOLVED", "review_required": True,
                                   "rationale": "Competing claims are preserved; no claim is silently selected."})
            for a in ids:
                for b in ids:
                    if a < b:
                        edges.append({"edge_id": stable_object_id("PE", [a,b,"CONTRADICTS"]),
                                      "source_node_id": a, "target_node_id": b,
                                      "edge_type": "CONTRADICTS", "rationale": cid})
    if len(nodes) > MAX_PROVENANCE_NODES or len(edges) > MAX_PROVENANCE_EDGES:
        raise ValueError("Provenance graph safety cap exceeded")
    node_ids = {n["node_id"] for n in nodes}
    if len(node_ids) != len(nodes): raise ValueError("Provenance node collision")
    # Origin pseudo-nodes are intentionally external anchors; all finding targets must exist.
    if any(e["target_node_id"] not in node_ids and e["edge_type"] != "CONTRADICTS" for e in edges):
        raise ValueError("Dangling provenance target")
    severity_counts = {x: sum(1 for e in items if e["severity"].lower()==x) for x in ("critical","high","medium","low","info")}
    by_module_counts = {}
    for e in items: by_module_counts[e["module"]] = by_module_counts.get(e["module"],0)+1
    nodes.sort(key=lambda n: n["node_id"])
    edges.sort(key=lambda e: e["edge_id"])
    contradictions.sort(key=lambda c: c["contradiction_id"])
    graph = {"schema_version": EVIDENCE_SCHEMA_VERSION, "ruleset_version": PROVENANCE_RULESET_VERSION,
             "nodes": nodes, "edges": edges, "contradictions": contradictions}
    graph["graph_hash"] = sha256_bytes(canonical_json_bytes(graph))
    return {"evidence": items, "total_evidence_count": len(items), "severity_counts": severity_counts,
            "by_module_counts": by_module_counts,
            "module_summaries": {k:v.get("summary",{}) for k,v in module_results.items()},
            "provenance_graph": graph,
            "dimensions": {"severity":"impact ordinal", "analytic_confidence":"analysis support ordinal",
                           "source_reliability":"source trust ordinal", "observation_status":"claim basis"}}
