# TRACE-X implementation status

**Validated:** 2026-09-23 (main 55b883a)
**Current suite:** 339 passed, 0 failed
**Implemented:** 20 modules - M01-M14 + M16-M21 (M19 audit chain, M20 local SQLite case store, M21 folder ingest)

## Working now

- Local `.eml` analysis from parser through report, linked evidence and deterministic risk.
- Batch-only M09 campaign correlation with exact per-indicator supporting investigation IDs.
- Typed, explainable, non-executable recommendations and deterministic policies.
- Offline IOC review exports, immutable feedback records and hash-linked local lifecycle records.
- M17 offline probable mail-infrastructure country lookup from DB-IP Lite Country 2026-09.
- M18 optional offline advisory probability with per-email token contributions.
- A loopback-only visual evidence workbench with risk/ML/hop/evidence visuals and details on demand.
- Private atomic JSON/TXT/manifest case publication and pre-download verification.
- One-click local ZIP export of those three verified case artifacts.
- One Windows launcher for setup, demo, CLI and tests.

## Invariants

- URLs are never visited and attachments are never executed.
- Authentication results are interpreted from reported headers, not independently verified.
- M17 is infrastructure-country context, not a person's location or attribution.
- M18 is INFO-level advisory evidence, never a verdict, score input or action trigger.
- Recommendations remain `executable=false`; no external action adapter exists.
- The manifest detects change but is not a signature or legal attestation.

## Partial/local-only

Campaign correlation sees one supplied batch. Policy, feedback and lifecycle records are local files without an authenticated service or RBAC. BEC logic uses bounded message evidence without mailbox history, relationship telemetry, reputation or financial-system verification.

## Not implemented

M15; automatic block/quarantine/delete/delivery/payment; mailbox or gateway connection; production API/database/multi-user case store; persistent campaign memory; independent DNS authentication verification; live reputation/WHOIS; production/compliance/legal-forensics claims.

## Readiness

- Prototype and controlled local testing: ready with stated limits
- Evidence-labeled hackathon demo: ready
- Production or live integration: not ready / not implemented

Historical 159, 164, 294, 297, 300, 328, 329 and 330-test results are milestones only. The current count is 339.
