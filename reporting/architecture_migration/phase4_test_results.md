# Phase 4 — Knowledge Projection Filtering & Retrieval Governance: Test Results

## Test commands and results

| Command | Result |
|---|---|
| `python -m wks.cli selftest` | PASS (ALL WKS GATE TESTS PASS) |
| `python eval/test_eligibility.py` | PASS (ALL ELIGIBILITY TESTS PASSED) |
| `python eval/test_wks.py` | PASS (ALL WKS GATE TESTS PASS) |
| `python eval/test_unified_ingest.py` | PASS |
| `python -m wks.domains --check` | 0 problem(s) across 70 classes |
| `python -m wks.project --check` | 0 problem(s) |
| `python -m wks.cli drift-audit` | 0 non-clean of 210 |
| `python -m wks.cli metrics` | (run; see metrics output) |
| `python -m wks.cli probe` | (run; see probe output) |
| `python -m wks.cli report` | (run; see report output) |

## Eligibility test coverage (eval/test_eligibility.py) — 27 scenarios

1. Supported item eligibility — PASS
2. High-confidence item eligibility — PASS
3. Discovered item exclusion (N/A state, documented) — PASS
4. Under-review item exclusion — PASS
5. Unresolved item exclusion (N/A state, documented) — PASS
6. Disputed item exclusion (N/A state, documented) — PASS
7. Outdated exclusion from current knowledge (N/A state, documented) — PASS
8. Rejected item exclusion — PASS
9. Open-conflict item exclusion — PASS
10. Missing-source item exclusion — PASS
11. Missing evidence relationship handling — PASS
12. Wrong-class retrieval prevention — PASS
13. Trust-prior non-bypass — PASS
14. FTS5 filtering — PASS
15. Investigation-mode status labelling — PASS
16. Historical-mode status labelling — PASS
17. CLASS.md projection filtering — PASS
18. DIGEST.md projection filtering — PASS
19. Attack-chain eligibility — PASS
20. Archived-path exclusion — PASS
21. Legacy-domain exclusion — PASS
22. Empty authoritative retrieval behaviour — PASS
23. Unified Learning/Research origin preservation — PASS
24. Retrieval context consistency — PASS
25. Projection manifest consistency — PASS
26. Rebuild reproducibility — PASS
27. Existing retrieval relevance probes — PASS

## Additional verification

- Agent context assembly: verified that ineligible records (under_review, rejected) never enter AUTHORITATIVE mode output. Verified by test 13 (trust-prior non-bypass) and 22 (empty retrieval).
- Quarantine/superseded: untouched; excluded from active reads (verified by tests 20, 21).
- No legacy fallback bypass: verified.
- ORCH authorization: not modified; regression not run separately but no ORCH files changed.
- Mastery/assessment: methodgen robustness fix applied; selftest T22/T23 now PASS.

## Status summary
- VERIFIED: eligibility module, retrieval filtering, projection filtering, drift audit, selftest, eligibility tests, domains check, project check.
- FAILED: none.
- BLOCKED: none.
- NOT RUN: external target testing (explicitly out of scope).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase4_test_results.md