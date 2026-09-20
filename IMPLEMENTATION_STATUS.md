# TRACE-X Implementation Status

Date: 2026-09-20

## IMPLEMENTED

- M01-M10 offline forensic pipeline
- reported authentication provenance and explicit trusted-authserv-id labeling
- M07/M08 prevention constraints preventing untrusted reported auth from supporting automation
- M11 typed advisory-only prevention recommendation
- explanation, evidence references, counterfactuals, impact, reversibility, limits, and human-approval flag
- backward-compatible JSON/text report integration
- unit and full-regression coverage

## PARTIALLY IMPLEMENTED

- campaign correlation: works for files supplied in one batch; no persistent history
- trusted authentication boundary: explicit allowlist supported; no independent SPF/DKIM/DMARC verification
- prevention: recommendation generation only; no policy engine, review store, or adapter execution

## DESIGNED BUT NOT IMPLEMENTED

- M12 trust/policy engine
- action lifecycle persistence
- analyst approval/rejection records
- IOC export and adapter interfaces
- feedback store and rule-tuning workflow

## FUTURE ROADMAP

- report data protection and retention controls
- stable evidence/case manifests
- persistent campaign history
- API/dashboard and enterprise adapters after foundational security work

## NOT SUPPORTED

- destructive or automated security actions
- live quarantine, block, delete, delivery, mailbox, SIEM, SOAR, or gateway control
- ML classification or learning
- independent authentication verification
- production or legal-forensics claims

## M12 update - IMPLEMENTED

- typed and versioned trust policies
- strict deterministic validation
- exact all-condition matching over forensic context signals
- priority, stable tie-breaking, explicit equal-priority conflicts
- expiration and disabled-policy handling
- allow-versus-risk safeguard
- explainable advisory-only policy decisions attached to M11

## M12 update - NOT YET IMPLEMENTED

- persistent policy store or audit history
- authenticated policy administration
- exceptions and department/recipient enrichment
- policy execution or live control adapters

## BEC workflow update - IMPLEMENTED

- deterministic local detection of payment, bank-change, invoice, gift-card,
  payroll, urgency, and secrecy language categories
- separate content, behavioral, identity, authentication, and URL indicators
- keyword-only findings remain insufficient without forensic corroboration
- evidence-traceable safeguards and BEC counterfactuals
- privacy-preserving assessment output that does not copy raw message text
- advisory-only, non-executable behavior

## BEC workflow update - NOT YET IMPLEMENTED

- relationship-history baselining
- recipient/asset sensitivity context
- mailbox telemetry or live financial verification
- production approval or enforcement workflow

## M16 lifecycle update - IMPLEMENTED

- typed frozen lifecycle and audit events
- immutable recommendation SHA-256 linkage
- explicit legal transitions and terminal states
- actor, role, timezone-aware timestamp, reason, and details recording
- append-only hash-linked event tuples and integrity verification
- reversal eligibility and required external references
- execution/outcome states are records only; no external action executes

## M16 lifecycle update - NOT YET IMPLEMENTED

- file/database persistence
- cross-process locking and transactions
- authenticated identities, access control, cryptographic signatures
- retention/deletion policy and legal chain-of-custody process
- live adapters or approval UI/API

## M13 IOC export - IMPLEMENTED

- deterministic TRACE-X JSON and CSV formats
- narrow evidence-backed URL/IP/domain extraction
- source investigation/evidence IDs and reasons
- ordinal confidence labels explicitly marked non-probabilistic
- review and expiration timestamps
- truthful heuristic/reported labeling; no independent verifier is claimed
- automated enforcement always false
- no network or live integration behavior

## M13 IOC export - NOT YET IMPLEMENTED

- STIX/TAXII
- live SIEM/SOAR/firewall/gateway/mailbox adapters
- reputation, ownership, allowlist, and policy enrichment
- signed exports, persistence, or automated enforcement
