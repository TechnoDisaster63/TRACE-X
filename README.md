# TRACE-X - Offline Email Investigation Workbench

**Current state (validated 2026-09-22): 17 implemented modules, 330 tests passing.**

TRACE-X analyzes analyst-supplied `.eml` files locally. It turns message structure, reported authentication headers, identity mismatches, route data and static URL features into linked evidence, a deterministic 0-100 risk score, threat classification, an advisory recommendation and a verified case package. It never visits URLs, executes attachments or takes an external action.

## Current modules

| Range | Capability |
|---|---|
| M01-M06 | Parsing, header forensics, reported SPF/DKIM/DMARC interpretation, identity checks, Received-chain reconstruction and static URL analysis |
| M07-M10 | Evidence normalization and provenance, deterministic risk, threat graph/campaign correlation and JSON/text reporting |
| M11-M14 | Non-executable recommendation, trust/policy evaluation, offline IOC export and immutable analyst-feedback records |
| M16 | Hash-linked local recommendation/action lifecycle records; records supplied facts, never performs an action |
| M17 | Offline DB-IP country lookup for public mail-hop IPs; probable infrastructure country only |
| M18 | Optional offline advisory phishing-language probability plus the tokens driving it; never changes the rule score |

M15 is intentionally absent because live action adapters are not implemented.

## Masterclass local console

Run `START-TRACE-X.bat` on Windows or `python demo.py`. The loopback-only evidence workbench opens at `http://127.0.0.1:8765/` and uses the same pipeline as the CLI.

The visual-first console shows:

- a deterministic risk dial and verdict hero;
- an M18 probability ring and contributing-token map;
- an M17 mail-hop path with compact infrastructure-country boundaries;
- severity counts with full evidence and provenance available on demand;
- a non-executable recommendation with reasons and limits on demand;
- an atomic case package with **EXPORT VERIFIED CASE - ZIP**.

The ZIP is assembled locally from exactly the generated investigation JSON, human-readable TXT report and integrity manifest. TRACE-X validates the case ID, confines lookup to the local output directory, re-verifies manifest hashes before download and blocks invalid or incomplete packages.

## Fresh local run on Windows

Use Python 3.11 from a PowerShell window. The second requirements file is needed for the bundled M18 model and the complete 330-test suite.

```powershell
git clone https://github.com/TechnoDisaster63/TRACE-X.git
cd TRACE-X
py -3.11 --version
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-ml.txt
python -m pip check
python -m pytest -q
python cli.py analyze test_data/phishing/phishing_paypal_lookalike.eml
python cli.py analyze test_data/legitimate/legit_newsletter.eml
python cli.py campaign test_data/campaign
python demo.py
```

Expected checks: `330 passed`, phishing `77/HIGH`, legitimate `0/LOW`, one three-message campaign, then the local console at `http://127.0.0.1:8765/`. Keep the PowerShell window open while using the console; press `Ctrl+C` to stop it. If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` once in that window, then activate again.

## One-click Windows launcher

`START-TRACE-X.bat` creates `.venv`, installs both requirement sets and opens the local console. That first bootstrap can require internet; analysis itself is offline.

```text
START-TRACE-X.bat
START-TRACE-X.bat analyze test_data\phishing\phishing_paypal_lookalike.eml
START-TRACE-X.bat campaign test_data\campaign
START-TRACE-X.bat test
```

The same entry points run on Linux/macOS after installing both `requirements.txt` and `requirements-ml.txt` in a virtual environment.

## Durable offline investigation controls

TRACE-X now keeps a local SQLite case index and a hash-chained append-only audit journal when analyses run through the CLI or console. Each audit entry binds the actor, action, case ID and input SHA-256 to the previous entry hash. This is a tamper-evident offline ledger, not a distributed blockchain and not a legal chain-of-custody attestation.

```bash
python cli.py analyze suspicious.eml --actor analyst-01
python cli.py verify-audit
python cli.py correlate-history
python cli.py watch-folder incoming_eml --actor ingest-01
```

`watch-folder` polls a local directory and analyzes each observed `.eml` once per running session. It is a local ingestion adapter, not a mail gateway or SIEM connector. Persistent correlation operates only over cases stored in the configured local SQLite database. See `docs/M18_DATASET_CARD.md` for the honest modern-evaluation plan; no new M18 score is claimed.

## Demonstrated behavior

- PayPal look-alike scenario: deterministic **77/HIGH**; M18 separately reports an advisory probability and exact driving tokens.
- Legitimate newsletter scenario: deterministic **0/LOW**; M18 remains separate and advisory.
- M09 campaign correlation is batch-only. Concrete indicator values retain exact supporting investigation IDs, including transitive clusters.
- Each console analysis publishes and verifies an atomic private case directory.
- One-click ZIP export was tested end to end for phishing and legitimate scenarios.

## Safety and honesty boundary

- Authentication is **reported-header analysis**, not independent SPF/DKIM/DMARC verification.
- URLs are parsed, never visited. Attachments are hashed/inspected as metadata, never executed.
- M17 reports probable mail-infrastructure country, never a person's location or actor attribution. No ASN, owner, WHOIS or reputation is claimed.
- M18 is INFO-level advisory evidence trained on historical public corpora. Held-out metrics are test-set-only, not field accuracy.
- Recommendations are advisory and `executable=false`.
- The manifest detects change. It is not a digital signature or legal chain-of-custody attestation.
- There is no live mailbox, gateway, SIEM/SOAR, authenticated service, database or autonomous enforcement.

## Validation

`330 passed` on 2026-09-22 with the optional M18 runtime installed. Coverage includes all implemented modules, the local console, verified ZIP export, unsafe/unknown export IDs, malformed input, safety invariants and integration scenarios.

## Key files

- `demo.py`, `demo_ui/` - loopback-only evidence workbench and verified ZIP endpoint
- `core/pipeline.py` - analysis, atomic case publication and verification
- `modules/` - M01-M14, M16-M18
- `demo_scenarios/`, `test_data/` - synthetic demonstration and regression inputs
- `docs/` - architecture, security, testing, evidence and project status
- `requirements-ci.txt` - hash-locked CI environment
- `requirements-ml.txt` - optional local M18 runtime

## Documentation

Start with [`docs/project/IMPLEMENTATION_STATUS.md`](docs/project/IMPLEMENTATION_STATUS.md), [`docs/security/LIMITATIONS_AND_NON_GOALS.md`](docs/security/LIMITATIONS_AND_NON_GOALS.md), [`docs/guides/HACKATHON_DEMO.md`](docs/guides/HACKATHON_DEMO.md) and [`docs/project/ROADMAP.md`](docs/project/ROADMAP.md).
