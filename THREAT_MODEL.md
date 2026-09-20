# Threat Model

Assets: raw email, evidence, reports, policy/recommendation/feedback/audit records. Adversaries may supply malformed/large MIME, forged headers, misleading domains/URLs, path-like names, duplicate signals, or tampered records.

Implemented mitigations: parser limits; no attachment/URL execution; output path controls; auth provenance; correlation decay; exact policy matching; immutable/hashes; fail-closed transitions/validation; no enforcement.

Residual threats: plaintext leakage, forged Authentication-Results without trusted boundary, parser resource exhaustion within caps, heuristic false positives/negatives, lack of authenticated actors, local filesystem tampering, no persistent transaction/locking. SSRF/redirect risks are absent because runtime performs no remote fetch.
