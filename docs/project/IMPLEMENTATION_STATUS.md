# TRACE-X implementation status

Current validation date: 2026-09-21

## What runs now

- M01-M10 analyze analyst-supplied `.eml` files locally: parsing, header and
  identity signals, reported-header authentication, route and static URL
  analysis, evidence linking, rule-based risk, threat patterns, and reports.
- M09 can correlate only the emails supplied together in the current process.
  It has no persistent campaign memory or live telemetry.
- M11 returns a typed recommendation with reasons, evidence references,
  counterfactuals, impact, reversibility, and limits.
- M12 evaluates deterministic, versioned policies. Policy results remain
  advisory and cannot silently weaken a stronger base recommendation.
- M13 exports deterministic JSON/CSV review aids with source evidence and
  expiration metadata. Automated enforcement is always false.
- M14 stores immutable local analyst-feedback records and produces review-only
  summaries. It does not tune rules or train a model.
- M16 models local lifecycle and hash-linked audit records. Execution/outcome
  states record supplied facts; they do not perform an external action.

That is 15 implemented modules: M01-M14 plus M16. M15 is absent because live
adapter execution is not implemented.

## Safety and evidence boundaries

- SPF, DKIM, and DMARC values come from reported `Authentication-Results`
  headers. TRACE-X does not independently verify them.
- URLs and attachments are never opened or executed.
- Risk and confidence are deterministic labels, not probabilities.
- Every recommendation is advisory and `executable=false`. Stronger
  recommendations require human approval.
- There is no mailbox, gateway, SIEM, SOAR, firewall, or financial-system
  connection.
- Reports are local plaintext artifacts and can contain sensitive message data.

## Partial or local-only capability

- Campaign correlation is process-local to one supplied batch.
- Trusted authserv IDs are caller-supplied labels, not independent
  authentication verification.
- Policies, feedback, lifecycle records, and exports have no secure persistent
  service, access control, or authenticated administration layer.
- BEC detection uses bounded local content and evidence heuristics. It has no
  relationship history, mailbox telemetry, reputation feed, or financial
  verification.

## Not implemented

- M15 or any live action adapter
- automatic block, quarantine, delete, delivery, payment, or other external act
- frontend, network API, database, secure multi-user case store, or approval UI
- persistent campaign history or live monitoring
- adaptive machine learning or automatic threshold/rule changes
- independent SPF, DKIM, or DMARC verification
- production, compliance, or legal chain-of-custody claims

## Readiness

- Prototype: **READY**
- Controlled local testing: **READY WITH LIMITS**
- Evidence-labeled hackathon demo: **READY**
- Production: **NOT READY**
- Live integration: **NOT IMPLEMENTED**

## Validation record

A fresh run from current `main` on 2026-09-21 collected 300 tests and passed all
300 with no failures. Historical 159, 164, 294, and 297-test runs remain in the
repository as dated audit milestones, not current test counts.
