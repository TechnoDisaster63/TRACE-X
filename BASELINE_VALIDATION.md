# TRACE-X Baseline Validation

Date: 2026-09-20  
Validated source: private `TechnoDisaster63/TRACE-X` `main`, initial audited baseline commit `91de0e9` (local source SHA-256 `6dc975283ceba64dabb9d51cf4af0d72746fd641f3af7506cb9cfc6c96d4230d`)  
Scope: inspection and validation only. No prevention feature is claimed or implemented by this document.

## Environment

- Linux validation environment
- Python `3.10.12` at `/usr/bin/python3`
- Project documentation states Python 3.11+, so this run also tests an older interpreter than documented
- Isolated virtual environment: `/tmp/trace-venv`
- Installed test dependency: `pytest 9.1.1`
- Runtime modules use the Python standard library only
- Offline execution; no DNS, URL retrieval, threat-intelligence, mailbox, delivery, SIEM, or gateway integration was exercised

## Exact commands

```bash
python3 -m venv /tmp/trace-venv
/tmp/trace-venv/bin/python -m pip install 'pytest>=7.4,<10'
/tmp/trace-venv/bin/python -m pytest -q
python3 cli.py --help
TRACE_X_OUTPUT_DIR=/tmp/trace-audit/out \
TRACE_X_REPORTS_DIR=/tmp/trace-audit/reports \
python3 cli.py analyze <sample.eml>
TRACE_X_OUTPUT_DIR=/tmp/trace-audit/out \
TRACE_X_REPORTS_DIR=/tmp/trace-audit/reports \
python3 cli.py campaign test_data/campaign
```

Representative `analyze` runs used these tracked samples:

- `test_data/legitimate/legit_newsletter.eml`
- `test_data/phishing/phishing_paypal_lookalike.eml`
- `test_data/bec/bec_ceo_wire_request.eml`
- `test_data/malformed/malformed_empty.eml`
- `test_data/malformed/malformed_truncated.eml`
- `test_data/phishing/lookalike_domain.eml`
- `test_data/phishing/suspicious_url_ip_shortener.eml`

## Test results

```text
........................................................................ [ 43%]
........................................................................ [ 87%]
....................                                                     [100%]
164 passed in 1.43s
```

- Passed: 164
- Failed: 0
- Skipped: 0
- Wall-clock wrapper measurement: 1.646 seconds

The previous count was not assumed. It was reproduced from the current source in a new virtual environment.

## CLI validation

`python3 cli.py --help` exited 0 and exposed the existing commands:

- `analyze`
- `analyze-folder`
- `campaign`

No prevention, policy, action, feedback, IOC-export, API, or integration command exists in this baseline.

## Representative execution results

| Sample | Exit | Measured wall time | Score / level | Threat class | Evidence | Parse warnings |
|---|---:|---:|---|---|---:|---:|
| legitimate newsletter | 0 | 119 ms | 0 / LOW | CLEAN | 1 | 0 |
| PayPal look-alike phishing | 0 | 85 ms | 77 / HIGH | PHISHING | 6 | 0 |
| CEO wire-request BEC | 0 | 90 ms | 52 / MEDIUM | BEC | 10 | 0 |
| empty malformed message | 0 | 83 ms | 48 / MEDIUM | INFRASTRUCTURE_ABUSE | 7 | 5 |
| truncated malformed message | 0 | 83 ms | 30 / MEDIUM | INFRASTRUCTURE_ABUSE | 6 | 2 |
| look-alike domain | 0 | 90 ms | 77 / HIGH | PHISHING | 6 | 0 |
| suspicious IP/shortener URL | 0 | 91 ms | 51 / MEDIUM | SPOOFING | 6 | 0 |

Times are single-run wall-clock measurements in this validation environment. They are not benchmarks and should not be used as capacity claims. Memory usage was not measured in the current validation environment.

Campaign execution over the three tracked campaign samples exited 0 in 107 ms. The implementation produced three individual investigations and a correlation result. This verifies bounded batch correlation for the tracked fixtures only, not persistent or cross-mailbox campaign detection.

## Existing output schema

A single saved investigation is JSON with these top-level keys:

```text
authentication, email_summary, evidence, file, file_sha256,
header_forensics, identity, investigation_id, parse_warnings,
processing_time_seconds, received_chain, report, risk,
threat_graph, url_analysis
```

The risk object includes score, risk level, confidence, factors, breakdown, explanation, and scoring method. The evidence object includes normalized evidence, severity and module counts, and summaries. The threat graph includes nodes, edges, threat patterns, classification, reasons, and summary. M10 also saves a human-readable text report.

## Reproducible findings and limitations

1. Authentication is reported-header analysis, not independent SPF/DKIM/DMARC verification. M03 parses `Authentication-Results` from the input message and does no DNS or cryptographic verification.
2. Authentication provenance is an index and copied header value only. There is no configured trusted receiving boundary or trusted `authserv-id`; an attacker-supplied header can therefore be interpreted as if it were authoritative.
3. `none` is kept distinct from `fail` in structured results, but M03 currently creates medium-severity weak-auth findings for DKIM/DMARC `none`; this needs context-aware review before prevention logic uses it.
4. Alignment is exact string comparison only. Organizational-domain alignment is not implemented.
5. The risk engine is deterministic and rule-based. Confidence labels are not calibrated probabilities.
6. Findings use module-local mutable counters. They reset per analysis and are not safe for concurrent execution.
7. Investigation IDs use a filesystem counter and are not a production chain-of-custody design.
8. Reports contain email content and forensic details in plaintext JSON/text. Access control, redaction, encryption, retention, and deletion policy are not implemented.
9. Campaign correlation operates only on the investigations supplied to one process. It has no persistent store, temporal index, or mailbox-wide history.
10. URL analysis is static and offline. URLs and attachments are not opened or executed, which is safe, but redirects and reputation are not verified.
11. No external threat intelligence, mailbox delivery, quarantine, sender blocking, SIEM, secure email gateway, database, API server, frontend, or live prevention action exists.
12. The malformed fixtures complete without crashing, but they receive risk classifications. Consumers must treat parse quality and missing context separately from maliciousness.
13. Output writes refuse overwrite, but JSON and text are separate writes rather than one atomic transaction.
14. Python 3.10.12 passed all tests although README says Python 3.11+. Supported-version policy and CI matrix are not yet defined.

## Blocking defects before prevention

- Establish a trusted boundary for `Authentication-Results`; preserve reported values while marking provenance and verification state.
- Prevent unverified/missing authentication observations from authorizing destructive recommendations.
- Protect or minimize sensitive report data before adding persistence or integrations.
- Remove mutable global finding counters before concurrency or an API.
- Define stable evidence identifiers and a tamper-evident case manifest before claiming chain of custody.
- Review M07 deduplication, M08 score/class consistency, and M09 `DMARC_NONE` semantics with regression tests.

## Recommended implementation order

1. Add trusted/untrusted authentication provenance and regression tests without changing the existing CLI contract.
2. Correct M03/M07/M08/M09 semantic defects surfaced by that provenance work.
3. Add report privacy controls and a case manifest.
4. Design M11 from the verified schemas, initially advisory-only and incapable of execution.
5. Add M12 policy validation and deterministic precedence.
6. Add approval lifecycle, offline IOC export, and immutable feedback only after M11/M12 are green.

## Baseline verdict

The current code is a working offline M01-M10 prototype with a green 164-test suite and reproducible CLI behavior. It is suitable for controlled internal testing and a hackathon demo when described as reported-header, heuristic analysis. It is not ready for production authentication, automated prevention, legal-forensics claims, or enterprise integration.
