# Limitations and non-goals

## Limits that affect every result

- **Reported authentication only.** SPF, DKIM, and DMARC values are parsed from
  message headers. TRACE-X does not query DNS or independently verify them.
- **Rule-based labels.** Risk and confidence are deterministic labels, not
  calibrated probabilities or proof of malicious intent.
- **Supplied batch only.** Campaign correlation sees only the files supplied to
  the current process. It has no persistent history or continuous telemetry.
- **Local plaintext output.** Reports can contain sensitive message data. The
  prototype has no access control, encryption, retention policy, or case store.
- **Bounded heuristics.** BEC, identity, brand, and URL rules can miss threats or
  flag legitimate messages. There is no external intelligence or mailbox
  history.
- **No service layer.** There is no frontend, network API, database, secure
  multi-user administration, or live enterprise integration.

## Not supported

TRACE-X does not perform autonomous block, quarantine, delete, delivery,
payment, URL visit, attachment execution, or any other external action. It has
no live mailbox, gateway, SIEM, SOAR, firewall, STIX/TAXII, monitoring, adaptive
ML, or blockchain capability. It does not claim production readiness,
compliance certification, legal chain of custody, 100% detection, or zero false
positives.
