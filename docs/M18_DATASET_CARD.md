# M18 dataset card and modern evaluation plan

## 1. Model, role, non-goals
M18 is an offline advisory phishing-language signal. It never changes TRACE-X's deterministic rule score and never authorizes an action. The current 0.99 F1 is historical-corpus test performance, not 2026 field accuracy.

## 2. Source inventory
| Source | Role | Time | License / check |
|---|---|---|---|
| Nazario + SpamAssassin | historical training baseline | ~2000s | existing bundled-model provenance |
| `cw-l/email-corpus` | modern malicious supplement + parser tests | created Mar 2026, 1,235 raw EML | MIT; redacted/defanged |
| Zenodo 13474746 phishing validation emails | locked external challenge set, never training | Aug 2024, 2,000 labeled | CC BY 4.0 |
| EPVME | adversarial regression only | modern, 49k synthetic | GPL-3.0 |
| SpaPhish v2 | multilingual drift test | through Oct 2025 | license must be verified before use |
| Sting9 weekly dump | rolling drift snapshot | rolling | CC0 claimed; record hash/count |

Before ingestion, store source URL, retrieval time, immutable archive SHA-256, record count, license evidence and any redistribution restriction. No new corpus has been downloaded or trained in this change.

## 3. Provenance fields
Every example must retain `source_id`, message date, label origin, language, license and SHA-256. Redaction/defanging is recorded, never hidden.

## 4. Processing and leakage control
Deduplicate exact bytes, normalized text and near-duplicate clusters before splitting. Keep campaigns, senders and duplicate clusters in one split. MeAJOR v2 and the 2023 curated set overlap Nazario/TREC; their aggregates must never cross train/test or support a combined score.

## 5. Time-aware source-disjoint split
Train through 2023, validate on 2024, then lock a 2025-26 source-disjoint test. Tune thresholds only on validation. Commit hash manifests for each split.

## 6. Training configuration
Pin code, dependency versions, seed, features, threshold and split-manifest hashes. Compare against a rules-only baseline. M18 remains advisory regardless of model choice.

## 7. Evaluation
Report PR-AUC, confusion matrix, precision/recall/F1, Brier score/calibration and bootstrap 95% confidence intervals, sliced by year, source and language. Lead with the locked modern challenge score when it exists; never blend it with the historical score.

## 8. Limitations
Old corpora are stylistically easy; modern data may be small, redacted or synthetic; labels may be source-specific; multilingual coverage is incomplete. An advisory can be confidently wrong. Test metrics are not production performance.

## 9. Ethics and legal
Honor corpus licenses and redistribution terms, minimize personal data, preserve defanging, and document removals. Do not visit URLs or execute attachments during preparation.

## 10. Maintenance and judge-facing claim
Quarterly drift review, or earlier if calibration/error slices breach locked tolerances. Snapshot rolling sources instead of silently changing the test.

> The 0.99 result is historical-only. We now define a locked source-disjoint modern challenge benchmark separately; M18 remains advisory. No modern benchmark score is claimed until the frozen evaluation is actually run.
