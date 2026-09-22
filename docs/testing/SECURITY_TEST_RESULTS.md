# Security Test Results

Date: 2026-09-20

- Current full suite (2026-09-22): **328 passed, 0 failed**, with the optional M18 runtime installed.
- Historical 2026-09-21 run: 300 passed; historical final-documentation run: 297 passed in 1.83s; retained as dated records, not the current count.
- Covers size/count limits, overwrite refusal, URL shortener boundary, provenance, non-execution, policy conflicts/expiration, keyword-only BEC rejection, lifecycle tamper/transition checks, IOC non-enforcement, feedback immutability/integrity.
- `python -m compileall -q core modules cli.py tests` passed in the final working tree.
- No dependency vulnerability scan, fuzz campaign, Windows execution, penetration test, memory profile, or external integration test was performed.
