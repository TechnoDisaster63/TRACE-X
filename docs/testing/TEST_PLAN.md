# Test plan

## Current gate

Run `python -m pytest -q`. The current release gate is **330 passed, 0 failed** with the optional M18 runtime installed.

## Covered

M01-M14 + M16-M18 units and integrations; legitimate/phishing/BEC/malformed samples; reported-auth provenance; route/IP/URL/domain edge cases; evidence/risk/graph/report invariants; policy conflict/expiry; lifecycle legality/tamper/reversal; IOC non-enforcement; immutable feedback; atomic case write/verification; demo API and UI; verified ZIP contents; unknown/unsafe export case IDs; campaign evidence attribution; graceful M17/M18 unavailable states.

## Required invariants

No URL visit, attachment execution or external action. M17 and M18 cannot change the deterministic score. M18 cannot become executable. Case export must remain confined to the output root and must fail closed on invalid integrity or incomplete artifacts.

## Still needed for production research

Real Windows launcher execution, multi-version/platform CI expansion, sustained fuzz/property testing, performance and memory profiles, dependency vulnerability review, authenticated-service testing, persistence/concurrency testing, adapter threat models and external penetration testing.
