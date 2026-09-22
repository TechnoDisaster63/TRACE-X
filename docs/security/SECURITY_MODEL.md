# Security Model

## IMPLEMENTED

Offline standard-library runtime; bounded EML size/counts; attachments never execute; URLs never fetch; safe output paths/exclusive writes; reported-auth provenance; untrusted auth cannot support automation; M11/M12/M13/M14/M16 non-execution flags; immutable/hash-linked records; strict validation; IOC automation disabled.

## PARTIALLY IMPLEMENTED

Tamper evidence exists at application-model level. Plaintext reports remain sensitive. IDs/counters and multi-file output are prototype designs.

## DESIGNED/FUTURE

Authenticated identities, authorization, encrypted storage, signatures, retention/deletion, atomic case transactions, dependency/CI scanning, sandboxed optional retrieval.

## NOT SUPPORTED

Production access control, independent auth verification, live enforcement, compliance certification, legal proof.
