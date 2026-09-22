# Prevention API Specification

## DESIGNED BUT NOT IMPLEMENTED

There is no network API. Current Python interfaces are:

- `generate_prevention_recommendation(...) -> dict`
- `evaluate_policies(...) -> dict`
- `assess_bec(...) -> dict`
- `build_ioc_export(...) -> dict`; `to_json`, `to_csv`
- `create_feedback_record`, `summarize_feedback`
- `create_lifecycle`, `transition_lifecycle`, `verify_lifecycle_integrity`

A future API must preserve typed schemas, authentication/authorization, idempotency, optimistic concurrency, audit records, size limits, and non-executable defaults. No endpoint, server, database, or production contract exists today.
