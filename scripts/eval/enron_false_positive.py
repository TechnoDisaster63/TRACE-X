"""Run TRACE-X over a seeded random sample of the CMU Enron corpus (2015-05-07 release).
Enron mail is (overwhelmingly) legitimate internal/business mail from 1999-2002, so this
measures how often TRACE-X flags real legitimate mail. It is NOT a phishing-detection test."""
import collections, json, random, sys, time, statistics
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.pipeline import analyze_email
root = Path(sys.argv[1]); files = [l.strip() for l in open(sys.argv[2]) if l.strip()]
out = Path(sys.argv[3]); out.mkdir(parents=True, exist_ok=True)
rows, errors = [], []
t0 = time.time()
for i, rel in enumerate(files):
    p = root / rel
    try:
        r = analyze_email(str(p))
    except Exception as e:
        errors.append({"file": rel, "error": repr(e)[:200]}); continue
    ev = r.get("evidence", {}).get("evidence", []) or []
    titles = [f"[{e.get('severity')}] {str(e.get('title') or e.get('description') or e.get('finding') or '')[:110]}" for e in ev if e.get("severity") in ("CRITICAL","HIGH","MEDIUM","LOW")]
    ml = r.get("ml_phishing_signal", {})
    rows.append({"file": rel, "score": r["risk"]["score"], "level": r["risk"]["risk_level"],
                 "class": r.get("threat_graph", {}).get("threat_class"), "ml_p": ml.get("phishing_probability"),
                 "findings": titles})
    if i % 200 == 0:
        (out/"progress.txt").write_text(f"{i+1}/{len(files)} done, {time.time()-t0:.0f}s, errors={len(errors)}\n")
json.dump({"rows": rows, "errors": errors}, open(out/"rows.json","w"))
n = len(rows); lv = collections.Counter(r["level"] for r in rows); cl = collections.Counter(r["class"] for r in rows)
scores = [r["score"] for r in rows]; mlp = [r["ml_p"] for r in rows if isinstance(r["ml_p"], (int,float))]
fc = collections.Counter(t for r in rows for t in set(r["findings"]))
hi = [r for r in rows if r["level"] in ("HIGH","CRITICAL")]
hfc = collections.Counter(t for r in hi for t in set(r["findings"]))
summ = {"sample_size_requested": len(files), "analyzed": n, "errors": len(errors), "seconds": round(time.time()-t0,1),
        "risk_level_counts": dict(lv), "threat_class_counts": dict(cl),
        "score_mean": round(statistics.mean(scores),2) if scores else None, "score_median": statistics.median(scores) if scores else None,
        "score_p95": sorted(scores)[int(0.95*(n-1))] if scores else None, "score_eq_0": sum(s==0 for s in scores),
        "ml_available": len(mlp), "ml_ge_0_5": sum(p>=0.5 for p in mlp), "ml_ge_0_9": sum(p>=0.9 for p in mlp),
        "top_findings_all": fc.most_common(15), "top_findings_in_high": hfc.most_common(10),
        "error_examples": errors[:5]}
json.dump(summ, open(out/"summary.json","w"), indent=1)
(out/"progress.txt").write_text("DONE\n")
