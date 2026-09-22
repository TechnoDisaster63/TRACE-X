# Test Plan

Unit and integration coverage spans M01-M14 + M16 + M17 + M18 implemented slices: legitimate/phishing/BEC/malformed messages; SPF/DKIM/DMARC reported states/provenance; multiple headers; IP/URL/domain edge cases; evidence/risk/graph/report; policy conflicts/expiry; BEC corroboration; lifecycle legality/integrity/reversal; IOC JSON/CSV; immutable feedback.

Fresh final command: `/tmp/tracex-final-venv/bin/python -m pytest -q`. Negative tests must fail closed. Existing M01-M10 compatibility must remain green. Future work: CI across supported Python/Windows, property/fuzz tests, performance/memory profiling, persistence/concurrency, security review.
