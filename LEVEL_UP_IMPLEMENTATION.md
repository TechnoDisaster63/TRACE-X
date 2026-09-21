# TRACE-X evidence reasoning and case-package implementation

This change implements the approved offline level-up without changing risk weights or thresholds.

- M07 emits a versioned, deterministic provenance graph while retaining the legacy `evidence` list. Content-derived IDs survive input order; all duplicate origins and source locators are preserved.
- Observation status, source reliability, analytic confidence and severity are separate ordinal fields. Reported SPF/DKIM/DMARC remains explicitly receiver-reported and never becomes independent verification.
- Contradictions are preserved as unresolved review records and can only keep or increase human review. Recommendations remain `executable=false`.
- `save_case()` stages JSON, text and a versioned integrity manifest in one private same-filesystem directory, flushes files, then publishes by directory rename. Existing cases are never overwritten. POSIX modes are 0700/0600 where supported.
- `verify-case` checks names, presence, size, SHA-256 and provenance graph hash. The manifest detects change; it is not a signature or legal chain-of-custody proof.
- Campaign reports carry batch-only replay material: sorted member investigation IDs and shared indicators. No attribution claim is made.

No database, API, cloud call, live enrichment, ML, automatic enforcement or new runtime dependency is added.
