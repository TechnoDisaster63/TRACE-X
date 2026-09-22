# TRACE-X implementation status

Current validation date: 2026-09-22

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
- M17 resolves public Received-hop IPs to probable mail-infrastructure country
  against the bundled offline DB-IP Lite Country 2026-09 database. Private,
  reserved, invalid, missing, and unknown IPs are reported explicitly and
  never guessed. This edition has no ASN, owner, WHOIS, or reputation fields.
- M18 adds one optional, offline, advisory ML phishing-language signal: a
  calibrated probability with per-email token explanations. It is INFO-level
  evidence only, is never executable, and never changes the deterministic
  risk score. Without the optional scikit-learn runtime or the bundled model
  it reports itself unavailable rather than guessing.

That is 17 implemented modules: M01-M14 plus M16, M17, and M18. M15 is absent
because live adapter execution is not implemented.

## Safety and evidence boundaries

- SPF, DKIM, and DMARC values come from reported `Authentication-Results`
  headers. TRACE-X does not independently verify them.
- URLs and attachments are never opened or executed.
- Risk and confidence are deterministic labels, not probabilities. The M18
  probability is a separate advisory signal, not the risk score.
- M17 countries describe probable mail infrastructure, never a person's
  location or actor attribution.
- M18 held-out metrics are test-set-only on historical 2005-2007-era public
  corpora. TRACE-X claims no field accuracy.
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
- adaptive/self-tuning machine learning or automatic threshold/rule changes
- independent SPF, DKIM, or DMARC verification
- production, compliance, or legal chain-of-custody claims

## Readiness

- Prototype: **READY**
- Controlled local testing: **READY WITH LIMITS**
- Evidence-labeled hackathon demo: **READY**
- Production: **NOT READY**
- Live integration: **NOT IMPLEMENTED**

## Validation record

A fresh run from current `main` on 2026-09-22 collected 328 tests and passed
all 328 with no failures, with the optional M18 runtime installed. Historical
159, 164, 294, 297, and 300-test runs remain in the repository as dated audit
milestones, not current test counts.
