# Security test results

**Validated 2026-09-22: 330 passed, 0 failed.**

The suite covers input size/count limits, traversal/overwrite refusal, malformed mail, URL non-fetching, attachment non-execution, evidence provenance, reported-auth boundaries, policy conflicts/expiry, BEC false-positive controls, lifecycle tamper/transitions, IOC non-enforcement, feedback integrity, M17/M18 fail-safe behavior, atomic case publication and verified ZIP export. Export regression tests confirm exactly three expected artifacts and rejection of unsafe/unknown case IDs.

`python -m compileall -q core modules cli.py tests` and CI compile/test gates are part of the repository workflow.

Not performed: external penetration test, dependency vulnerability scan, long fuzz campaign, Windows execution, resource profile or live integration test.
