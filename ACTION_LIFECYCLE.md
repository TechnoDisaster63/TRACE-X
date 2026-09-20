# Action Lifecycle

- **IMPLEMENTED:** immutable M16 typed lifecycle, legal transitions, hash-linked audit events, recommendation linkage, integrity checks, reversal records.
- **PARTIALLY IMPLEMENTED:** EXECUTED/FAILED only record an external adapter outcome; no adapter exists.
- **NOT SUPPORTED:** persistence, live execution, legal chain-of-custody claim.

States: PENDING, REVIEW_REQUIRED, APPROVED, REJECTED, EXECUTED, FAILED, EXPIRED, REVERSED, CANCELLED. Every event records actor/role/time/reason/details. Equal timestamps are allowed; sequence and hashes order events. Reversal requires an executed reversible lifecycle and reference. The model never changes external state.
