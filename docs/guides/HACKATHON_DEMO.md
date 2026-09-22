# SIH 2026 Demonstration Flow

Project: TRACE-X, Zyronith, SIH26106.

1. State the boundary: offline prototype, reported-header authentication, no live blocking.
2. Double-click `START-TRACE-X.bat` (or run `python demo.py`): the offline console opens. Point out the boundary chips and the bundled scenario pack.
3. Run the legitimate scenario in the console: show LOW/CLEAN, the M17 geo table (probable infrastructure countries of the hops), and the M18 advisory ML panel with a low probability and its driving tokens.
4. Run the phishing scenario: show 77/HIGH/PHISHING, evidence IDs, the M18 probability and exact contributing tokens, HOLD_FOR_REVIEW recommendation, executable=false, auth provenance limits. Say clearly: the ML signal is advisory INFO evidence; the score comes from deterministic rules.
5. Run `python cli.py analyze test_data/legitimate/legit_newsletter.eml`: show LOW/CLEAN and request-additional-analysis due to no risk evidence.
6. Run the BEC fixture: show 52/MEDIUM/BEC, payment/urgency plus identity/auth corroboration, analyst review, out-of-band and financial safeguards, counterfactuals.
7. Run the malformed fixture: show parse warnings and explain anomalies are not proof; M17/M18 report explicit unavailable states rather than guessing when data is missing.
8. Run `python cli.py campaign test_data/campaign`: show three investigations and one batch campaign; say batch-only, not continuous telemetry.
9. Show deterministic IOC JSON/CSV with source evidence, expiry, heuristic status, enforcement=false.
10. Show feedback and lifecycle demo artifacts: immutable linkage, review-only summaries, no action execution.

Say "advisory ML signal with token explanations and test-set-only metrics". Never say verified SPF/DKIM/DMARC, real-time protection, ML-powered verdicts, production-ready, zero false positives, live integration, or legal proof.
