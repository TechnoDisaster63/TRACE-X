# TRACE-X Source Architecture Map

Date: 2026-09-20  
Status: inventory of the current M01-M10 baseline. This file distinguishes verified implementation from proposals.

## Project root and layout

The project root contains `cli.py`, `core/`, `modules/`, `tests/`, `test_data/`, `output/`, `reports/`, `README.md`, `AUDIT_REPORT.md`, batch launchers, and `requirements.txt`. There are 67 tracked files in the audited package. Python source totals about 4,867 lines including tests.

## Processing flow

```text
.eml file
  -> M01 parse_eml
  -> M02 analyze_headers
  -> M03 analyze_authentication
  -> M04 analyze_identity
  -> M05 analyze_received_chain
  -> M06 analyze_urls
  -> M07 build_evidence_bundle
  -> M08 compute_risk
  -> M09 build_threat_graph
  -> M10 generate_report
  -> JSON investigation + text report
```

`core.pipeline.analyze_email` is the integration boundary. `analyze_campaign` runs the same flow for each file and then invokes M09 batch correlation.

## Implementation inventory

| Path / module | Responsibility | Public interface | Main input | Main output | Dependencies | Existing tests | Modification risk | Proposed integration point |
|---|---|---|---|---|---|---|---|---|
| `cli.py` | CLI routing and console summary | `cmd_analyze`, `cmd_analyze_folder`, `cmd_campaign`, `main` | paths and trusted-domain options | console + saved reports | argparse, pipeline | integration tests exercise behavior | High: compatibility | Add future commands only after M11/M12 stabilize |
| `core/config.py` | limits, output paths, risk thresholds, static URL lists | constants | environment | configuration values | stdlib | indirect + hardening tests | High: broad fan-out | Centralize policy-independent prevention defaults here or a new config module |
| `core/models.py` | shared findings and parsed-email models | `Finding`, `Attachment`, `ParsedEmail`, `findings_summary` | normalized values | dataclasses/dicts | dataclasses | all modules | High: schema contract | Add new prevention models separately; do not overload forensic evidence |
| `core/utils.py` | hashes, paths, logging, IDs | `sha256_*`, `safe_join`, ID functions | bytes/paths | hashes/safe paths/IDs | stdlib | investigation and hardening tests | High: integrity | Replace counters/manifest in forensic-integrity work |
| `core/pipeline.py` | M01-M10 orchestration and writes | `analyze_email`, `analyze_campaign`, save functions | `.eml` path(s) | full investigation dict | all modules | M01-M10 integration | Critical | Attach M11 after completed forensic result, advisory-only at first |
| `m01_eml_parser/parser.py` | bounded MIME/header/body/URL/attachment parsing | `parse_eml` | path or bytes | `ParsedEmail` | email, pathlib, models/config | parser + hardening | Critical: untrusted input | Preserve raw auth headers and source order; keep offline limits |
| `m02_header_forensics/analyzer.py` | header anomaly observations | `analyze_headers`, `reset_counter` | `ParsedEmail` | findings dict | regex, email utils | dedicated tests | Medium | Feed evidence only; no action decisions |
| `m03_auth_analyzer/analyzer.py` | reported SPF/DKIM/DMARC parsing and string alignment | `analyze_authentication`, `reset_counter` | `ParsedEmail` | structured auth + findings | regex, models | dedicated + integration | Critical | Add trusted-boundary/provenance state before prevention |
| `m04_identity_analyzer/analyzer.py` | identity mismatch and impersonation heuristics | `analyze_identity`, `reset_counter` | `ParsedEmail`, trusted domains | identity findings | regex, email utils | dedicated tests | High: false positives | M12 supplies versioned trust context later |
| `m05_received_chain/analyzer.py` | Received-chain and IP observations | `analyze_received_chain`, `reset_counter` | `ParsedEmail` | hops + findings | regex | dedicated tests | High: provenance/IP semantics | Use only evidence with explicit uncertainty |
| `m06_url_analyzer/analyzer.py` | static URL normalization/signals | `analyze_urls`, `reset_counter` | `ParsedEmail.urls` | URL findings | urllib.parse, config | dedicated + hardening | High: IOC quality | M13 exports only qualified indicators; never fetch by default |
| `m07_evidence_engine/engine.py` | normalize and deduplicate M02-M06 findings | `build_evidence_bundle`, `reset_counter` | module result dicts | evidence bundle | models/utils | dedicated + integration | Critical: traceability | Stable evidence IDs and provenance precede M11 |
| `m08_risk_engine/engine.py` | capped deterministic score, confidence and level | `compute_risk` | evidence bundle | risk dict | config | dedicated + integration | Critical: downstream decision | M11 consumes but never equates score with proof |
| `m09_threat_graph/engine.py` | graph, classification, in-process campaign correlation | `build_threat_graph`, `correlate_campaign` | evidence/risk or investigations | graph/campaign dict | stdlib | graph + campaign tests | Critical: semantic overclaim | Add policy/action nodes only after evidence semantics are fixed |
| `m10_report_generator/engine.py` | JSON/text report model and narrative | `generate_report`, `to_json`, `to_text` | investigation components | report dict/text | stdlib | report + integration tests | High: sensitive data | Append backward-compatible prevention section after M11 |
| `tests/` | unit, integration, regression coverage | 16 test files | fixtures/code | pytest assertions | pytest | 164 pass | Low | Add regression tests beside each change |
| `test_data/` | legitimate, phishing, BEC, malformed, edge, campaign fixtures | generated/static `.eml` | n/a | reproducible samples | none | used throughout | Medium: representativeness | Add adversarial auth/policy/prevention fixtures |
| `output/`, `reports/` | local generated artifacts | filesystem directories | investigation | JSON/text | pipeline | hardening tests | Critical: privacy | Add redaction/retention/access guidance before wider use |

## Verified current features

- Local `.eml` parsing with input and count limits
- Header, reported-authentication, identity, routing, and static URL analysis
- Normalized evidence and deterministic explainable risk scoring
- Per-email threat graph and bounded multi-email correlation
- JSON and text investigation reports
- SHA-256 of input and attachments
- CLI and automated pytest suite

## Not implemented

- Independent SPF evaluation, DKIM cryptographic verification, or DMARC DNS/policy validation
- External threat intelligence or safe remote URL retrieval
- Mailbox ingestion, delivery control, quarantine, sender/domain/URL blocking
- Prevention recommendation schema, trust policy engine, approval lifecycle, action adapters
- Database, API, frontend, access control, retention engine, live SIEM/SOAR/SEG integration
- ML classifier, model training/evaluation, calibrated probabilities

## Data models and formats

- `ParsedEmail` is the M01 internal record.
- `Finding` is the shared M02-M06 observation contract.
- M07 emits dictionaries rather than a typed evidence dataclass.
- M08, M09, and M10 exchange JSON-serializable dictionaries.
- Reports are JSON plus plain text; no schema version exists for the whole investigation object, while M10 includes its own report version.

## Risk scoring inventory

M08 uses deterministic severity weights and caps grouped evidence to reduce duplicate inflation. Thresholds are `CRITICAL >= 80`, `HIGH >= 55`, `MEDIUM >= 30`, otherwise `LOW`. Its confidence label is derived from evidence confidence/count and is not a probability. Threat class is assigned separately in M09 from graph patterns and evidence categories.

## Duplicate and overlapping logic

- Module-local `_counter` dictionaries and `reset_counter` repeat in M02-M07.
- Domain extraction/normalization occurs independently in header, authentication, identity, URL, and graph modules.
- Authentication and identity modules both perform domain alignment-like checks with different context.
- M10 has recommendation wording, but it is report guidance, not a structured prevention engine or action lifecycle.
- M08 score reasoning and M09 threat-pattern reasoning overlap but represent different concepts; they need explicit contracts rather than merging.

## Security-sensitive operations

- Untrusted MIME/header parsing and bounded body/attachment handling
- File reads, SHA-256, output path construction, state counter, and exclusive output writes
- Unicode/domain/URL parsing and IP classification
- Plaintext report generation containing potentially sensitive body-derived evidence
- Global mutable finding counters and non-transactional multi-file output

No shell command execution, archive extraction, unsafe deserialization, attachment execution, URL fetching, mailbox write, or live security-control action is present in the runtime code.

## Campaign-correlation assessment

Campaign correlation is genuinely implemented for a supplied batch. It groups investigations by shared indicators and emits campaign structures with scores and confidence. It is partial in product terms because it is process-local, fixture-sized, has no persistence or temporal store, and does not correlate unseen mailbox history. Marketing should say "batch campaign correlation," not continuous campaign intelligence.

## Smallest safe architecture change

1. Extend M03 results with explicit provenance and trust state while preserving current result fields.
2. Add regression tests for multiple headers, absent/unknown auth service, `none` versus `fail`, and unverified reported passes/fails.
3. Carry provenance through M07 and prevent M08/M09 from treating untrusted reported authentication as verified fact.
4. Only then add a new typed M11 recommendation object after M10 input assembly, initially advisory-only with no adapter execution.

This order fixes an evidence-boundary defect before any action-selection logic can amplify it.
