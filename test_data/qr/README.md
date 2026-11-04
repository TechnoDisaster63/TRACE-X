# M22 QR evidence test fixtures

Synthetic .eml fixtures for the optional M22 QR evidence module. Every file was
generated locally for the issue #39 renderer/isolation experiments (no real
mail, no live URLs; example.org / 192.0.2.1 documentation endpoints only).

- `manifest.json`: per-fixture sha256 and the expected QR payload set. The
  `*_tiny.eml` fixtures carry valid payloads that the OpenCV detector cannot
  decode at 38x38 px; tests assert they do NOT decode (documented limit).
- Provenance: generated and hash-recorded 2026-11-04 in the round-1 experiment
  bundle (ZIP sha256 67860728eb4387ddd9afb0edcefca36b63675e05bac54a292f64f977499cdd18),
  re-verified unchanged in round 2. `byte_limit.eml` is not committed (2.8 MB);
  tests build an equivalent oversize-part message in a tmp dir at runtime.
