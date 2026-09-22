# TRACE-X R&D roadmap

## Phase 0 - judge-ready prototype (current)

Merge the audited campaign-evidence fix, masterclass console, verified ZIP export and current-truth docs. Rehearse the evidence-led demo. Keep every claim inside the existing offline/advisory boundary.

## Phase 1 - service foundation

Build an authenticated service and secure case store before integrations: stable schemas, encrypted persistence, tenant/identity model, RBAC, approvals, retention/redaction, audit access, concurrency controls, migration strategy and operational telemetry.

## Phase 2 - read-only mail adapters

Add narrowly scoped mailbox ingestion only after Phase 1. Preserve raw-source identity, least privilege, replay protection, rate controls and clear separation between collection and analysis. No write/quarantine permission.

## Phase 3 - SIEM output

Publish versioned, evidence-linked findings to a SIEM/ticket workflow with idempotency and delivery receipts. Keep recommendations advisory.

## Phase 4 - modern ML evaluation

Train/evaluate on licensed, recent, representative data. Define drift, calibration, subgroup and adversarial tests before considering any production role. The bundled M18 model remains a historical-corpus demo signal.

## Phase 5 - controlled actions last

M15 begins only after RBAC, approval and audit controls are proven. Start with reversible ticket creation. Do not begin with delete, quarantine or payment-impacting actions. Require explicit human approval, scoped adapters, rollback and outcome evidence.

## Deferred until the foundation exists

Live threat feeds, WHOIS/reputation, persistent campaign memory and active response. These are not bolt-ons; they require privacy, SSRF, licensing, provenance, availability and false-positive controls.
