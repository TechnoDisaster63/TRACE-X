# Limitations and Non-Goals

## Current limitations

Reported-header authentication only; no DNS/DKIM verification. Rule-based risk/confidence, not probabilities. Process-local batch campaign correlation. Plaintext outputs. No persistent policy/audit/feedback store. No API/UI/database/access control. No external intelligence or mailbox history. Heuristic BEC/identity/URL logic can err. Performance is single-run local timing, not a benchmark.

## Non-goals/currently not supported

Autonomous blocking/quarantine/deletion; financial action; attachment/URL execution; live SIEM/SOAR/firewall/gateway/mailbox; STIX/TAXII; ML/adaptive learning; blockchain; production/compliance/legal claims; 100% detection/zero false positives.
