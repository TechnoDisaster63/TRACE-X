# TRACE-X — Email Forensic Investigation & Campaign Intelligence Platform

**Status: PROTOTYPE (M01-M12 advisory-only).** This is a Python-only core analysis
engine. It has no frontend, no API server, and no database. It is not a
production security product and does not constitute legal or regulatory
proof of anything.

## 1. What TRACE-X Is

TRACE-X takes one or more `.eml` files and produces an evidence-based,
rule-based forensic analysis: header anomalies, SPF/DKIM/DMARC
interpretation, sender-identity impersonation checks, mail-routing
reconstruction, static URL analysis, a normalized/de-duplicated evidence
bundle, a transparent risk score, a threat-pattern classification, optional
multi-email campaign correlation, a structured investigation report, and an advisory-only explainable prevention recommendation.

## 2. Current Prototype Scope (M01-M11)

| Module | Purpose |
|---|---|
| M01 | EML Parser — normalizes a raw `.eml` into structured data |
| M02 | Header Forensics — Reply-To/Return-Path/Message-ID anomalies |
| M03 | SPF/DKIM/DMARC Analyzer — authentication signal interpretation |
| M04 | Identity Analyzer — display-name and domain impersonation checks |
| M05 | Received-Chain Analyzer — mail routing path reconstruction |
| M06 | URL Analyzer — static structural analysis of URLs (never visited) |
| M07 | Evidence Engine — normalizes/dedupes findings from M02-M06 |
| M08 | Risk Engine — deterministic, correlation-aware score (0-100) and risk level |
| M09 | Threat Graph — per-email node/edge graph, threat-pattern classification, **and multi-email campaign correlation** |
| M10 | Report Generator — full investigation report (JSON + human-readable text) |
| M11 | Prevention Recommendation Engine — typed, explainable, non-executable advisory output |
| M12 | Trust and Policy Engine — typed, versioned, deterministic advisory policy decisions |

**Not yet built / explicitly out of scope for this build:** persistent policy administration,
action execution/adapters, frontend, API server, database, cloud services, and
machine-learning classification. M11 is rule-based and advisory-only.

## 3. Requirements

- Windows 10/11 for the included batch launchers (the Python CLI also runs on Linux/macOS)
- Python 3.11 or newer, available on PATH
- No internet access required at runtime
- No API keys required

## 4. Installation

1. Unzip this package anywhere (e.g. `C:\TRACE-X`).
2. Open a Command Prompt in that folder.
3. Run `setup.bat`.

## 5. Running setup.bat

`setup.bat`:
- Verifies Python is installed and prints its version
- Creates a `.venv` virtual environment (if missing)
- Activates it and upgrades pip
- Installs `requirements.txt`
- Creates `output\` and `reports\` if missing
- Runs a basic import check
- Prints `SETUP RESULT: SUCCESS` or `SETUP RESULT: FAILURE`
- Pauses so you can read the result

**Note:** `setup.bat`/`run.bat` were validated by executing the equivalent
steps (venv creation, pip install, import check) directly on Linux in the
development sandbox, since no Windows host was available there. The batch
syntax itself has not been executed on a real Windows machine — see
Section 11.

## 6. Running run.bat

`run.bat` activates the virtual environment automatically — you never
need to activate it yourself.

```
run.bat
run.bat analyze test_data\phishing\phishing_paypal_lookalike.eml
run.bat analyze-folder test_data\campaign
run.bat campaign test_data\campaign
run.bat test
```

## 7. CLI Commands

```
python cli.py analyze <path\to\email.eml> [--trusted-domains a.com b.com]
python cli.py analyze-folder <path\to\folder> [--trusted-domains a.com b.com]
python cli.py campaign <path\to\folder> [--trusted-domains a.com b.com]
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
module (M01-M11) and into both saved output files. IDs persist across
separate CLI process invocations (via a small counter file in `output\`),
so running the CLI multiple times — or against multiple files — never
reuses an ID.

## 8. Test Commands

```
run.bat test
```
or, with the virtual environment active:
```
python -m pytest tests\ -v
```

As of this build: **206 real, executed tests, all passing** — unit tests
for M01-M10, dedicated investigation-ID regression tests (including
subprocess-level reproduction of the original ID-collision bug), dedicated
campaign-correlation tests, dedicated M08 double-counting/correlation
tests, and full M01→M10 integration suites run against every synthetic
sample in `test_data\`. No test results in this project are fabricated;
anything not verified is reported as such.

## 9. Project Structure

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
│   └── m12_trust_policy/
├── core/
│   ├── pipeline.py       (wires M01->M12; analyze_email + analyze_campaign)
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
├── reports/
├── output/
├── cli.py
├── requirements.txt
├── setup.bat
└── run.bat
```

## 10. Security Limitations

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
- No DNS lookups are performed anywhere in M01-M10 (SPF/DKIM/DMARC and
  domain-alignment checks are string/header analysis only, not live
  verification).
- No shell commands are ever executed based on email content.
- No secrets, API keys, or hard-coded credentials anywhere in the project.
- The investigation-ID counter file uses a simple cross-platform
  exclusive-create lock with a stale-lock timeout — adequate for a
  single-user prototype CLI, not designed for heavy concurrent access.

## 11. Current Limitations

- Look-alike/typosquat detection in M04 requires the caller to supply
  `trusted_domains` explicitly for domain-specific comparisons; a small
  built-in heuristic set covers a few very well-known brands even
  without that context, but this is intentionally limited in scope.
- The brand-impersonation list (M04/M06) is a small, hardcoded,
  illustrative set — not a comprehensive brand-protection database.
- The risk engine (M08) is a transparent, additive, correlation-aware
  rule-based model, not a trained machine-learning classifier (M11 —
  RiskClassifier ML — is intentionally not part of this build).
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
- `setup.bat`/`run.bat` batch-file syntax has been reasoned through and
  the underlying Python steps verified on Linux, but not executed on an
  actual Windows machine in this environment.
- This is a prototype for validating detection logic, not a hardened,
  production-ready security tool.

## Audit hardening applied (2026-09-20)

This audited package removes the bundled virtual environment, caches, and prior generated reports. It enforces documented parser collection limits, rejects oversized byte input, prevents silent report overwrite, recovers the investigation counter from existing outputs, supports output paths through `TRACE_X_OUTPUT_DIR` / `TRACE_X_REPORTS_DIR`, and fixes exact shortener-domain matching. See `AUDIT_REPORT.md` for remaining limitations.
