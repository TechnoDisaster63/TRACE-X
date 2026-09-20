# TRACE-X full project audit

**Audit date:** 2026-09-20  
**Scope:** supplied archive, including setup, source, architecture, security, dependencies, tests, performance, CLI flow, documentation, packaging, and demo readiness.

## Verdict

TRACE-X is a credible, unusually well-tested **offline prototype**, not a production email-authentication or forensic-verification system. The core M01-M10 pipeline is cohesive and fast on the included data. I independently ran the original suite: **159/159 tests passed in 1.29 seconds** under Python 3.10.12. The audited package adds five regression tests; **164/164 passed in 1.46 seconds**.

The biggest risk is semantic rather than code execution: SPF, DKIM, and DMARC values are parsed from unverified `Authentication-Results` text. TRACE-X does not establish a trusted receiving boundary or verify those mechanisms. A forged or incorrectly trusted header can therefore affect findings and risk scores. The README partly discloses the no-DNS limitation, but live demos must describe the values as *reported header claims*, not verified authentication.

**Readiness:** good for a controlled local demo using synthetic `.eml` files; not ready for production decisions, incident attribution, legal evidence, hostile bulk ingestion, a web/API deployment, or claims of independent SPF/DKIM/DMARC verification.

## Independent checks

| Check | Result |
|---|---|
| Archive safety | 2,921 ZIP entries; no absolute paths, traversal entries, or symlinks found |
| Original tests | 159 passed, 0 failed, 1.29 s |
| Hardened tests | 164 passed, 0 failed, 1.46 s |
| Python compile | Passed for core, modules, CLI, and tests |
| CLI help | Worked |
| Single-email CLI demo | Worked and produced JSON/text output |
| Runtime network calls | No network client use found in project source |
| Dangerous execution primitives | No `eval`, `exec`, `os.system`, or production `subprocess` use found |
| Secrets scan | No credential material found; the only token-like text was synthetic phishing sample data |
| Windows launchers | Reviewed, but not executed on Windows |
| API/UI | None exists, as documented |

## Prioritized findings

### P0 - must be explicit before any real-world use

#### 1. Authentication results are not cryptographically verified

`modules/m03_auth_analyzer/analyzer.py` trusts the first `Authentication-Results` header containing each mechanism and interprets its text. The tool cannot know whether that header was added by a trusted receiver. It also does no DNS, DKIM signature, SPF, or DMARC-policy verification. Header order alone is not a trust boundary.

**Impact:** forged or untrusted headers can produce misleading authentication status, alignment, evidence, score, and report language.

**Fix:** require a configured trusted authentication service identifier and discard `Authentication-Results` outside that boundary, or integrate a real verifier. Rename displayed fields to "reported SPF/DKIM/DMARC" until then. Add adversarial tests for attacker-prepended headers and conflicting trusted/untrusted headers.

#### 2. Output contains sensitive message data without access controls

The JSON report persists addresses, subject lines, header data, URLs, evidence, routing data, and other email-derived content as ordinary files. The original package also shipped 139 generated output/report files.

**Impact:** real investigations may leak personal or incident data through backups, source control, archive sharing, or multi-user machines.

**Fix:** use a private per-user data directory, create files with restrictive permissions, define retention/deletion, add a `--redact` mode, and never distribute generated case files. The audited package removes prior generated reports, but OS-level access controls and redaction remain open.

### P1 - required before production or hostile bulk input

#### 3. Declared parser limits were mostly dead configuration

The original `core/config.py` declared limits for attachments, URLs, and Received hops, but the parser did not apply them. The 25 MB limit only applied to path input, not byte input. Reproduction on the supplied code accepted a 25 MB + 1 byte byte string, 600 URLs, and 60 Received headers.

**Impact:** memory/CPU amplification and oversized reports from hostile inputs.

**Applied in audited package:** byte-size enforcement, URL/Received/attachment-count caps, oversized-attachment hash suppression, and regression tests. Further work should cap decoded text size, multipart depth/part count, header length, total decoded payload, and campaign batch size.

#### 4. Investigation IDs could overwrite earlier evidence

The original counter reset to 1 if its state file was missing/corrupt, even when `TX-000001.json` already existed. Saves used write mode and silently replaced an existing report. This was reproduced during audit.

**Impact:** evidence loss and broken traceability.

**Applied in audited package:** recovery from existing JSON IDs, atomic counter replacement, exclusive-create report writes, and regression tests. For production, use random immutable IDs or a transactional database and record chain-of-custody events.

#### 5. Global mutable finding counters are not thread-safe

Analyzer modules reset module-level counters for each run. Concurrent analyses in one process can interleave resets/increments and generate duplicate or unstable finding IDs.

**Impact:** an eventual API or parallel worker can produce inconsistent evidence IDs.

**Fix:** replace globals with per-analysis local counters or derive stable IDs after findings are assembled. Add multithread/process tests before adding an API.

#### 6. Forensic integrity is incomplete

Input SHA-256 is useful, but reports are not signed; there is no acquisition timestamp/source record, immutable event log, custody trail, tool-build identifier, deterministic environment manifest, or verification command.

**Impact:** reports are analysis artifacts, not tamper-evident forensic records.

**Fix:** add a manifest with tool version/commit, input hash, configuration, execution environment, UTC times, report hash, and optional digital signature. Keep original evidence read-only.

### P2 - quality and accuracy

#### 7. URL and IP heuristics can misclassify

The original shortener check used substring matching, so a host such as `bit.ly.evil.example` could be labeled a known shortener. IPv4 detection accepts syntactically shaped but invalid values such as `999.999.999.999`. Domain alignment uses exact string equality rather than organizational-domain rules.

**Applied:** exact/domain-boundary shortener matching plus tests.  
**Remaining:** use `ipaddress`, IDNA normalization, and Public Suffix List-based registrable-domain comparison where appropriate.

#### 8. Package was bloated and non-portable

The 38 MB project included a 34 MB Windows virtual environment, 1,151 `.pyc` files, caches, and 139 generated reports. Virtual environments are machine-specific and should not be shipped.

**Applied:** the audited package excludes the virtual environment, bytecode, caches, and generated reports; it is about 374 KB before zipping. Output/report directories retain only `.gitkeep`.

#### 9. Dependency setup is not reproducible

Runtime code is standard-library-only, which is a strong design choice. Test setup allows a broad pytest range and `setup.bat` upgrades pip from the network without hashes or a lock file.

**Fix:** separate runtime and developer dependencies, pin tested versions, add a lock/hash strategy, add CI for supported Python/Windows versions, and document offline installation.

#### 10. CLI exit behavior is automation-unfriendly

Folder commands catch per-file failures and continue but do not return a failing process status; no-files and too-few-files paths also return success. This makes scripted demos/CI unable to reliably detect partial failure.

**Fix:** count failures and return a nonzero exit code; add `--fail-fast`, `--json-summary`, and quiet modes.

#### 11. Architecture has clear modules but oversized report/graph files

The pipeline boundary and dataclasses are readable. However, the threat-graph and report modules are large, loosely typed dictionaries are passed across module boundaries, and module schemas are implicit.

**Fix:** define typed result models/schemas, split correlation from graph construction and text rendering from report assembly, and version the JSON schema.

#### 12. Performance is fine for the demo, not bounded for scale

The included suite runs quickly and the pipeline is sequential. Campaign correlation and rich report duplication can grow substantially with batch size. There are no benchmarks, memory tests, malformed-input fuzzing, or upper-bound tests.

**Fix:** add benchmark fixtures, memory/timeout assertions, parser fuzzing, a configurable maximum batch size, and profiling on large representative mail.

## UI/API and flow assessment

There is no UI or API to audit. The actual flow is:

`.eml` path -> parse -> M02-M06 independent analyzers -> evidence normalization -> risk score -> graph/classification -> report -> JSON/text files.

That is appropriate for a prototype. Do not bolt the CLI directly onto an internet-facing upload endpoint. An API needs authentication, authorization, request and decompression limits, isolated workers, timeouts, rate limits, private storage, schema validation, audit logs, safe error handling, and concurrency fixes first.

## Demo readiness checklist

1. Use the clean audited package, not the original archive.
2. Install Python 3.11+ and run `setup.bat` on a real Windows machine once before presenting.
3. Run `run.bat test`; expect 164 passing tests.
4. Demo with the supplied synthetic samples only.
5. Say "static, reported-header analysis" rather than "SPF/DKIM/DMARC verification."
6. Show both a legitimate and phishing sample, then the campaign command.
7. Explain that no URL is fetched and no attachment is executed.
8. Keep the explicit prototype disclaimer visible.
9. Clear `output/` and `reports/` before packaging or screen-sharing.
10. Have a fallback terminal recording because Windows batch syntax was not independently executed in this audit environment.

## Applied changes in the audited package

- Removed bundled `.venv`, caches, bytecode, and prior case outputs.
- Enforced documented input collection limits, including byte input.
- Added warnings when URL/Received/attachment collections are truncated.
- Prevented silent report overwrite.
- Made counter updates atomic and recoverable from existing output IDs.
- Added `TRACE_X_OUTPUT_DIR` and `TRACE_X_REPORTS_DIR` support.
- Fixed shortener matching to respect domain boundaries.
- Added five focused hardening tests.
- Updated README portability and audit notes.

## Recommended delivery order

1. Authentication trust boundary and accurate terminology.
2. Private/redacted output and forensic manifest.
3. Remove global counters and add concurrency safety.
4. Parser fuzzing and remaining resource limits.
5. Reproducible dependencies and Windows CI.
6. Typed/versioned result schemas and reliable CLI exit codes.
7. Only then consider an authenticated API or UI.
