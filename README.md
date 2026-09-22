# TRACE-X — Email Forensic Investigation & Campaign Intelligence Platform

**Status: PROTOTYPE (17 modules: M01-M14 + M16 + M17 + M18; 328 tests passing).**
This is a Python analysis engine with a local, loopback-only demo UI. It has no
network-facing frontend, API server, or database. It is not a production
security product and does not constitute legal or regulatory proof of anything.

## 1. What TRACE-X Is

TRACE-X takes one or more `.eml` files and produces an evidence-based,
rule-based forensic analysis: header anomalies, SPF/DKIM/DMARC
interpretation, sender-identity impersonation checks, mail-routing
reconstruction, static URL analysis, offline geo/infrastructure
intelligence, an advisory offline ML language signal, a
normalized/de-duplicated evidence bundle, a transparent risk score, a
threat-pattern classification, optional multi-email campaign correlation, a
structured investigation report, and an advisory-only explainable prevention
recommendation.

## 2. Current Prototype Scope (M01-M14 + M16 + M17 + M18)

| Module | Purpose |
|---|---|
| M01 | EML Parser — normalizes a raw `.eml` into structured data |
| M02 | Header Forensics — Reply-To/Return-Path/Message-ID anomalies |
| M03 | SPF/DKIM/DMARC Analyzer — authentication signal interpretation |
| M04 | Identity Analyzer — display-name and domain impersonation checks |
| M05 | Received-Chain Analyzer — mail routing path reconstruction |
| M06 | URL Analyzer — static structural analysis of URLs (never visited) |
| M07 | Evidence Engine — normalizes/dedupes findings from M02-M06, M17 and M18 |
| M08 | Risk Engine — deterministic, correlation-aware score (0-100) and risk level |
| M09 | Threat Graph — per-email node/edge graph, threat-pattern classification, **and multi-email campaign correlation** |
| M10 | Report Generator — full investigation report (JSON + human-readable text) |
| M11 | Prevention Recommendation Engine — typed, explainable, non-executable advisory output |
| M12 | Trust and Policy Engine — typed, versioned, deterministic advisory policy decisions |
| M13 | IOC Export — deterministic offline TRACE-X JSON/CSV review aids; never automated enforcement |
| M14 | Analyst Feedback — immutable offline decision records and review-only tuning summaries |
| M16 | Prevention audit model — immutable recommendation linkage and validated offline lifecycle records |
| M17 | Geo/Infrastructure Intelligence — offline DB-IP country lookup for public Received-hop IPs |
| M18 | Advisory ML Phishing Signal — optional offline calibrated probability with per-email token explanations |

**Not yet built / explicitly out of scope for this build:** persistent policy administration,
action execution/adapters (M15), network-facing frontend/API server, database, and cloud
services. M11 stays rule-based and advisory-only. M18 is an advisory evidence signal: it never
changes the deterministic risk score and never triggers an action.

## 3. Requirements

- Windows 10/11 for the included batch launcher (the Python CLI and demo also run on Linux/macOS)
- Python 3.11 or newer, available on PATH (Python 3.10 also works)
- Internet access once, for the first-run dependency install only; analysis itself is fully offline
- No API keys required

## 4. One-Click Start (Windows)

Double-click **`START-TRACE-X.bat`** — the only startup file you need.

- First run: it creates the `.venv` environment, installs `requirements.txt`
  (plus the optional offline ML runtime, best effort), and verifies the install.
  This first run needs internet; every run after that is fully offline.
- Every run: it opens the TRACE-X demo console in your browser.
- It also wraps the CLI and the test suite, so no other launcher is needed:

```
START-TRACE-X.bat                  :: demo console (same as double-click)
START-TRACE-X.bat analyze test_data\phishing\phishing_paypal_lookalike.eml
START-TRACE-X.bat analyze-folder test_data\campaign
START-TRACE-X.bat campaign test_data\campaign
START-TRACE-X.bat test
```

**Note:** the launcher's steps (venv creation, pip install, import check) were
validated by executing the equivalent steps directly on Linux in the
development sandbox, since no Windows host was available there. The batch
syntax itself has not been executed on a real Windows machine — see
Section 11.

## 5. CLI Commands (any platform)

```
python cli.py analyze <path/to/email.eml> [--trusted-domains a.com b.com]
python cli.py analyze-folder <path/to/folder> [--trusted-domains a.com b.com]
python cli.py campaign <path/to/folder> [--trusted-domains a.com b.com]
```

- `analyze` / `analyze-folder` — analyze one or every `.eml` in a folder
  independently. Each run writes a structured M11 prevention assessment into JSON/text output and prints a summary (Investigation ID, Risk
  Level/Score, Threat Classification, Top Findings, Evidence Count,
  Confidence) and writes the full JSON result to
  `output\<Investigation-ID>.json` plus a human-readable text report to
  `reports\<Investigation-ID>.txt`.
- `campaign` — analyzes every `.eml` in a folder (each still gets its own
  unique Investigation ID and full report) **and additionally** correlates
  them into campaigns based on real, shared, observable indicators (sender
  domain, Reply-To domain, shared URL host, display name, similar subject
  pattern). Only emails that actually share a concrete indicator with
  another email in the batch are grouped; unrelated/legitimate emails are
  correctly left uncorrelated.

`--trusted-domains` is optional context for M04's look-alike/typosquat
detection. TRACE-X never assumes a domain is legitimate on its own —
trust must be supplied explicitly by the caller.

### Investigation IDs

Every investigation gets a unique `TX-XXXXXX` ID. This ID is generated
**once** per `analyze_email()` call and propagates unchanged through every
module and into both saved output files. IDs persist across
separate CLI process invocations (via a small counter file in `output\`),
so running the CLI multiple times — or against multiple files — never
reuses an ID.

## 6. Test Commands

```
START-TRACE-X.bat test
```
or, with the virtual environment active:
```
python -m pytest tests\ -v
```

**328 tests pass on current `main` (validated 2026-09-22).** The suite covers
the complete offline pipeline, case packaging and demo interface — unit tests
for every module M01-M14 + M16 + M17 + M18, dedicated investigation-ID
regression tests (including subprocess-level reproduction of the original
ID-collision bug), dedicated campaign-correlation tests, dedicated M08
double-counting/correlation tests, M17 geo fallbacks, M18 advisory-signal
invariants, and full integration suites run against every synthetic sample in
`test_data\`. No test results in this project are fabricated; anything not
verified is reported as such.

## 7. Project Structure

```
trace-x/
├── modules/
│   ├── m01_eml_parser/
│   ├── m02_header_forensics/
│   ├── m03_auth_analyzer/
│   ├── m04_identity_analyzer/
│   ├── m05_received_chain/
│   ├── m06_url_analyzer/
│   ├── m07_evidence_engine/
│   ├── m08_risk_engine/
│   ├── m09_threat_graph/        (threat graph + campaign correlation)
│   ├── m10_report_generator/
│   ├── m11_prevention_recommendation/
│   ├── m12_trust_policy/
│   ├── m13_ioc_export/
│   ├── m14_analyst_feedback/
│   ├── m16_prevention_audit/
│   ├── m17_geo_infra_intel/     (offline DB-IP country data bundled)
│   └── m18_ml_phishing_signal/  (optional offline advisory ML probability + token contributions)
├── core/
│   ├── pipeline.py       (wires M01->M11 + M17 + M18; analyze_email + analyze_campaign)
│   ├── models.py
│   ├── config.py
│   └── utils.py          (incl. persistent investigation-ID generator)
├── test_data/
│   ├── legitimate/
│   ├── phishing/
│   ├── bec/
│   ├── campaign/
│   ├── malformed/
│   └── edge_cases/
├── tests/
├── docs/                 (architecture, guides, project, reports, security, specifications, testing)
├── demo_ui/              (loopback-only local demo interface)
├── demo_scenarios/
├── reports/
├── output/
├── cli.py
├── demo.py
├── requirements.txt
├── requirements-ml.txt   (optional offline M18 inference runtime)
├── requirements-ci.txt   (hash-locked CI/test environment, CPython 3.10+)
└── START-TRACE-X.bat     (single one-click launcher: bootstrap + demo + CLI + tests)
```

## Documentation

Supporting architecture, security, testing, project, and report documents are indexed in [`docs/README.md`](docs/README.md).

## 8. Security Limitations

- All `.eml` input is treated as untrusted.
- Attachments are **never executed**; only metadata (filename, content
  type, size, SHA-256) is extracted.
- HTML bodies are parsed for text only; `<script>`/`<style>` content is
  discarded, never executed.
- URLs are **never visited or fetched** — analysis is purely structural
  (scheme, host, path, query, known-shortener/keyword heuristics).
- Filenames are sanitized against path traversal before any filesystem
  use.
- Input file size is capped (25 MB) to reduce resource-exhaustion risk.
- No DNS lookups are performed anywhere in the pipeline (SPF/DKIM/DMARC and
  domain-alignment checks are string/header analysis only, not live
  verification; M17 geo lookups read a bundled local database file).
- No shell commands are ever executed based on email content.
- No secrets, API keys, or hard-coded credentials anywhere in the project.
- The M18 model artifact is bundled locally and loaded only from disk; if the
  optional ML runtime or the artifact is unavailable, the signal reports
  itself unavailable instead of guessing.
- The investigation-ID counter file uses a simple cross-platform
  exclusive-create lock with a stale-lock timeout — adequate for a
  single-user prototype CLI, not designed for heavy concurrent access.

## 9. Current Limitations

- Look-alike/typosquat detection in M04 requires the caller to supply
  `trusted_domains` explicitly for domain-specific comparisons; a small
  built-in heuristic set covers a few very well-known brands even
  without that context, but this is intentionally limited in scope.
- The brand-impersonation list (M04/M06) is a small, hardcoded,
  illustrative set — not a comprehensive brand-protection database.
- The risk engine (M08) is a transparent, additive, correlation-aware
  rule-based model. The M18 ML signal is deliberately separate from it:
  an INFO-level advisory evidence item whose held-out metrics are
  test-set-only on historical public corpora (2005-2007 era), not a
  field-accuracy claim.
- M17 resolves only probable mail-infrastructure **country** from the
  bundled DB-IP Lite Country edition — never a person's location or actor
  attribution — and this edition has no ASN, owner, WHOIS, or reputation
  fields, so those stay explicitly unavailable.
- Campaign correlation (M09) compares only the emails supplied together
  in a single `campaign` batch; it does not persist state across runs or
  query any external threat-intelligence source. It also does not yet
  correlate on attachment hashes (no attachment-hash data is currently
  threaded through to the correlation layer).
- No PDF report generation; reports are structured JSON plus a
  human-readable `.txt` rendering.
- No persistent storage/database beyond the small investigation-ID
  counter file; each CLI invocation is otherwise stateless beyond the
  JSON/text files it writes.
- `START-TRACE-X.bat` batch-file syntax has been reasoned through and
  the underlying Python steps verified on Linux, but not executed on an
  actual Windows machine in this environment.
- This is a prototype for validating detection logic, not a hardened,
  production-ready security tool.

## Audit hardening applied (2026-09-20)

This audited package removes the bundled virtual environment, caches, and prior generated reports. It enforces documented parser collection limits, rejects oversized byte input, prevents silent report overwrite, recovers the investigation counter from existing outputs, supports output paths through `TRACE_X_OUTPUT_DIR` / `TRACE_X_REPORTS_DIR`, and fixes exact shortener-domain matching. See `docs/reports/AUDIT_REPORT.md` for remaining limitations.

## Continuous integration

GitHub Actions runs a bounded validation job for every pull request to
`main`, every push to `main`, and manual dispatches. It installs the exact
CPython 3.11 test environment from `requirements-ci.txt` with SHA-256 hash
verification, checks dependency consistency, compiles the Python sources and
tests, and runs the full test suite. Third-party actions are pinned to full
commit SHAs, workflow permissions are read-only, and the job has a 10-minute
timeout. `requirements-ci.txt` hashes every published wheel of each pinned
version, so the same hash-locked install also works on CPython 3.10-3.13
across platforms.

This CI proves only that these repository checks pass in the stated GitHub
runner environment. It is not a vulnerability scan, production certification,
live integration test, Windows test, or substitute for independent security
review. Runtime analysis remains offline and standard-library-only.


## Evidence reasoning and private case packages

Each analysis includes an additive `evidence.provenance_graph` with stable evidence IDs, source locators, preserved origins and explicit unresolved contradictions. Legacy evidence fields remain available. Severity, analytic confidence, source reliability and observation status are deliberately separate.

CLI analysis publishes a private case directory containing JSON, text and a versioned integrity manifest. Verify it offline:

```bash
python cli.py verify-case output/TX-000001
```

The verifier detects missing or changed artifacts. It does not authenticate the analyst or replace chain-of-custody procedures. Authentication findings remain reported-header analysis, not independent SPF/DKIM/DMARC verification. All recommendations remain advisory and non-executable.

## Offline SIH demo interface

Run the local judge-facing interface with the standard library only:

```bash
python demo.py
```

(or double-click `START-TRACE-X.bat` on Windows, which bootstraps and launches it)

It opens `http://127.0.0.1:8765/` and accepts a local `.eml` upload or one of six synthetic demo scenarios. It calls the same deterministic pipeline as the CLI and shows, as first-class panels: the deterministic risk score with contributions, linked evidence with IDs and preserved origins, the **M17 geo/infrastructure table** (probable infrastructure country per public hop IP, explicit unavailable states), the **M18 advisory ML signal** (calibrated phishing-language probability with the exact tokens that drove it, labeled advisory-only with test-set-only metrics), and the advisory recommendation with `executable=false` and its human-approval boundary. Each run publishes and immediately verifies the same private atomic case package used by the CLI.

The server is loopback-only. It adds no API service, database, or cloud call. Email URLs are never visited, attachments are never executed, authentication stays reported-header analysis unless a trusted receiving boundary is explicitly configured, and campaign correlation stays batch-only. The browser page itself is a local presentation layer, not a network-facing product interface.

The bundled scenario guide is in [`demo_scenarios/README.md`](demo_scenarios/README.md). For campaign correlation, use the existing batch command rather than treating one uploaded email as persistent campaign evidence:

```bash
python cli.py campaign test_data/campaign
```

## M17 offline geo/infrastructure intelligence

TRACE-X resolves public M05 hop IPs against the bundled **DB-IP Lite
Country 2026-09** MMDB. Analysis makes no network call. Results describe
probable mail-infrastructure country, not a person's location or actor
attribution. Missing, corrupt, private/reserved, and unknown-IP cases report
unavailable/internal explicitly and never guess. This DB edition contains no
ASN, owner, WHOIS, or reputation data, so those fields remain unavailable.
See `modules/m17_geo_infra_intel/data/README.md` for source, version, license,
and SHA-256.

M11 also includes a small versioned, offline TF-IDF/cosine BEC phrase
similarity layer. It cites the exact reference phrase and is explicitly not a
trained classifier. M09 can build sender trust relationships only from
explicit analyst feedback; absence of history is unknown, not malicious.

CLI additions: `export-ioc`, `feedback`, and `lifecycle`. All remain offline,
advisory-only, and non-executable.

## M18 advisory ML phishing signal

TRACE-X bundles a small, user-trained logistic-regression model
(`tracex_ml_v2`, SHA-256 recorded in `modules/m18_ml_phishing_signal/README.md`)
that produces exactly one INFO-level advisory evidence item per email: a
calibrated phishing-language probability plus the positive per-email TF-IDF
token contributions that drove it, so a judge can see *why* the number moved.
Inference runs fully offline against the same cleaner used in training.

Hard boundaries, enforced by tests: the signal never changes the deterministic
M08 risk score, never marks anything executable, and degrades to an explicit
UNAVAILABLE state (never a guess) when the optional scikit-learn runtime or the
model artifact is missing. Its held-out phishing F1 (0.99 on a 648-sample test
split of historical Nazario + SpamAssassin corpora) is a test-set-only figure
on 2005-2007-era data; TRACE-X makes no field-accuracy claim and no claim that
the signal overrides deterministic rules. Install the optional runtime with
`pip install -r requirements-ml.txt`.
