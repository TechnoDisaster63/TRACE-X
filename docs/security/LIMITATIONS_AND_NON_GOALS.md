# Limitations and non-goals

## Result boundaries

- SPF/DKIM/DMARC are reported-header observations; TRACE-X does not independently verify DNS authentication.
- Risk is deterministic and rule-based. M18's probability is separate INFO-level advisory evidence.
- M18 metrics come from a historical public-corpus test split and are not field accuracy.
- M17 gives probable mail-infrastructure country only, never personal location or actor attribution; no ASN/owner/WHOIS/reputation is present.
- Campaign correlation sees only the supplied batch.
- Brand, BEC, identity and URL checks are bounded heuristics.
- Local JSON/TXT/ZIP outputs can contain sensitive message data. No authenticated case service, encryption-at-rest policy or retention service exists.

## Export boundary

The console ZIP contains exactly the generated JSON report, TXT report and integrity manifest. Integrity is re-verified before download. The manifest detects local changes; neither it nor the ZIP is a signature or legal chain-of-custody attestation.

## Non-goals in this prototype

No URL visit, attachment execution, live mailbox, gateway, SIEM/SOAR, firewall, STIX/TAXII, autonomous block/quarantine/delete/delivery/payment, adaptive learning, ML enforcement, production-readiness, certification, perfect detection or legal proof.
