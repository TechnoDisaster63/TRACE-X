# Changelog

## 2026-09-20 - Prevention prototype foundation

Added baseline/architecture documentation; Authentication-Results provenance; M07/M08 prevention constraints; advisory M11 and BEC workflow; deterministic M12 policies; offline M13 JSON/CSV IOC export; immutable M14 feedback; immutable/hardened M16 lifecycle; expanded regression coverage and truthful status/readiness docs. No live execution, API, ML, or production claim added.

## 2026-09-22 - M17 geo intelligence, M18 advisory ML, and repo polish

Added M17 offline geo/infrastructure intelligence (bundled DB-IP Lite Country 2026-09; probable infrastructure country only; explicit unavailable states) and M18 optional offline advisory ML phishing signal (calibrated probability, per-email token explanations, INFO-level, never changes the deterministic score, explicit unavailable fallback). Suite now 328 tests.

Polish pass: docs rewritten to the true 17-module state; demo UI surfaces M17 geo and M18 probability/tokens as first-class labeled panels; `START-TRACE-X.bat` is now the single self-contained one-click launcher (bootstrap + demo + CLI + tests), absorbing `setup.bat`/`run.bat`; `requirements-ci.txt` now hashes every published wheel of each pin so the locked install works on CPython 3.10-3.13, not only the CI runner's 3.11; pipeline metadata/docstrings updated to M01-M14+M16+M17+M18. No live execution, API, production, or field-accuracy claim added.
