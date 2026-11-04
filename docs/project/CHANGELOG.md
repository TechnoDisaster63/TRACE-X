# Changelog

## 2026-11-04 - Optional M22 QR evidence

- Added M22, an opt-in offline module that recovers QR code payloads from PNG/JPEG and PDF attachments as INFO-level advisory evidence (`cli.py analyze --qr-evidence`, or `analyze_email(..., enable_qr_evidence=True)`). pypdf embedded-image fast path with pypdfium2 (PDFium) render fallback; OpenCV decoding.
- Measured bounds from the issue #39 experiments: 2 MiB per part, 4M pixels, 3 pages, 8 parts, 10s wall timeout, plus POSIX RLIMIT_CPU/RLIMIT_AS around the worker subprocess. Explicit statuses for encrypted, malformed, blank and limit-hit parts.
- Default pipeline behaviour is unchanged; M22 never changes the deterministic score and degrades to an explicit UNAVAILABLE finding when its optional runtime (requirements-qr.txt) is missing.
- 30 hash-recorded synthetic fixtures in test_data/qr: 21/24 QR-bearing fixtures fully recovered; the three 38x38px fixtures are documented as below the OpenCV detector limit.
- Optional runtime licences verified permissive for MIT distribution (docs/licenses/QR_EVIDENCE_RUNTIME.md). PyMuPDF (AGPL/commercial) deliberately excluded.
- Suite: 376 passed, 0 failed.

No live action, network API, sandbox claim, production-readiness or field-accuracy claim was added. OS-level isolation for hostile files and real-mail evaluation remain open (issues #39, #38).

## 2026-09-22 - Current judge-ready prototype

- Added M17 offline DB-IP probable infrastructure-country intelligence with explicit unavailable states.
- Added M18 offline advisory phishing-language probability and contributing tokens; bundled model SHA-256 `307c0674d6a50e81b3d323d66c34cb2d6e10f3e6338005a0f381bc94970999bd`.
- Fixed transitive M09 campaign evidence attribution by retaining exact investigation support per concrete indicator value.
- Replaced the generic demo with the TRACE-X masterclass evidence workbench: risk dial, verdict hero, ML ring/token map, hop path, severity rail, on-demand details and signature casework visual system.
- Removed the problem-statement number from the product UI.
- Added verified one-click local case ZIP export (JSON + TXT + manifest), fail-closed on invalid/incomplete packages.
- Consolidated Windows startup into `START-TRACE-X.bat` and fixed hash-locked CI dependencies.
- Rewrote current documentation and set the current validation record to 330 passing tests.

No live action, network API, production, field-accuracy or legal-forensics claim was added.

## 2026-09-20 - Prevention prototype foundation

Added evidence provenance and prevention constraints, typed advisory recommendations, deterministic policies, BEC workflow, offline IOC review export, immutable feedback and hash-linked local lifecycle records.
