# SIH demo scenario pack

The interface exposes six existing, synthetic `.eml` fixtures: legitimate, phishing, BEC, look-alike, malformed and one campaign member. No scenario changes pipeline weights or expected outcomes. Campaign correlation remains a separate batch-only CLI operation; selecting one campaign member does not claim persistent or cross-run correlation.

Suggested judge flow: legitimate baseline, phishing evidence/provenance, BEC human-approval boundary, malformed uncertainty, then `python cli.py campaign test_data/campaign` for batch-only campaign correlation.
