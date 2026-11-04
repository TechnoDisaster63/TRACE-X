# M22 - QR Evidence (optional, opt-in, offline)

M22 recovers QR code payloads from image (`image/png`, `image/jpeg`) and PDF
attachments and records them as INFO-level advisory evidence. It answers one
question only: "which payloads are encoded in this message's QR images?"

It is not a detector. A decoded payload is evidence, not a verdict, never a
score input (INFO carries 0 points in M08), and decoded URLs are recorded,
never visited. TRACE-X stays fully offline.

## Enabling

- CLI: `python cli.py analyze file.eml --qr-evidence`
- API: `analyze_email(path, enable_qr_evidence=True)`
- Runtime: `pip install -r requirements-qr.txt`. Without it, M22 returns an
  explicit `UNAVAILABLE` finding and the rest of the pipeline is unaffected.
- Default behaviour is unchanged: M22 runs only when opted in.

## Processing

Extraction runs in a child process (`worker.py`) so limits isolate the main
pipeline from renderer faults:

1. MIME walk; only PNG/JPEG/PDF parts are candidates (cap: 8 parts).
2. Per-part byte cap (2 MiB) before any decode.
3. Images: pixel cap (4,000,000) before decode; OpenCV QRCodeDetector,
   multi-code first, single-code fallback.
4. PDFs: page cap (3). Fast path extracts embedded images with pypdf (no
   rasterization); pages without embedded images are rendered with pypdfium2
   (PDFium) at 1.5x as fallback, with a pre-render pixel check. If pypdf
   cannot parse the file at all, all pages go through pypdfium2. Encrypted
   PDFs that do not open with an empty password are reported `encrypted`,
   never brute-forced.
5. Process guard: 10s wall timeout; on POSIX also RLIMIT_CPU 8s and
   RLIMIT_AS 1 GiB (reported in the result as `guard`). On non-POSIX systems
   only the wall timeout applies and the result says so.

## Recorded evidence

Each decoded payload yields one finding: payload text, `is_http_url`,
attachment SHA-256, MIME part index, PDF page when applicable, renderer used
(`pypdf-embedded`, `pdfium-render`, `direct`), and decoder version. Per-part
statuses are explicit: `decoded`, `not_decoded`, `malformed`, `encrypted`,
`byte_limit`, `pixel_limit`, `page_limit`, `part_limit`, plus process-level
`timeout` / `worker_terminated` / `worker_error`.

## Measured behaviour (synthetic fixtures, issue #39 rounds 1-2)

- 21/24 QR-bearing fixtures recovered their full expected payload set
  (rotations, JPEG re-encode, blur, low contrast, embedded in PDF, multiple
  codes per image, non-URL text payloads).
- The three 38x38 px fixtures do not decode (OpenCV detector limit) and return
  `not_decoded`. This is a documented limitation, not silent success.
- Slowest fixture 162 ms; full suite under the guard peaked at 83.6 MB RSS.
- Real-mail recovery effectiveness is unmeasured and waits on issue #38.

## Security boundary

The bounds limit runaway CPU, memory, wall time and input size. They are NOT
a security sandbox, and the worker's Python-level socket denial can be bypassed
by native renderer code. Parsing hostile attachments needs OS-level isolation
(container / seccomp / network namespace) that this prototype does not ship.
See `docs/security/LIMITATIONS_AND_NON_GOALS.md`.

Licences for the optional runtime: `docs/licenses/QR_EVIDENCE_RUNTIME.md`.
