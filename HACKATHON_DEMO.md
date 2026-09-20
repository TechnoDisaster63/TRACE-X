# SIH 2026 Demonstration Flow

Project: TRACE-X, Zyronith, SIH26106.

1. State the boundary: offline prototype, reported-header authentication, no live blocking.
2. Run `python cli.py analyze test_data/legitimate/legit_newsletter.eml`: show LOW/CLEAN and request-additional-analysis due to no risk evidence.
3. Run phishing fixture: show 77/HIGH/PHISHING, evidence IDs, HOLD_FOR_REVIEW recommendation, executable=false, auth provenance limits.
4. Run BEC fixture: show 52/MEDIUM/BEC, payment/urgency plus identity/auth corroboration, analyst review, out-of-band and financial safeguards, counterfactuals.
5. Run malformed fixture: show parse warnings and explain anomalies are not proof.
6. Run `python cli.py campaign test_data/campaign`: show three investigations and one batch campaign; say batch-only, not continuous telemetry.
7. Show deterministic IOC JSON/CSV with source evidence, expiry, heuristic status, enforcement=false.
8. Show feedback and lifecycle demo artifacts: immutable linkage, review-only summaries, no action execution.

Never say verified SPF/DKIM/DMARC, real-time protection, ML-powered, production-ready, zero false positives, live integration, or legal proof.
