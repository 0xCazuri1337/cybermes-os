# Phase 5 — Test Results

## Test commands and results

| Command | Result |
|---|---|
| `python eval/test_hunt_history.py` | PASS (10 tests, OK) |
| `python eval/test_wks.py` | PASS (ALL WKS GATE TESTS PASS) |
| `python eval/test_eligibility.py` | PASS (ALL ELIGIBILITY TESTS PASSED) |
| `python eval/test_unified_ingest.py` | PASS |
| `python -m wks.cli selftest` | PASS (ALL WKS GATE TESTS PASS) |
| `python -m wks.domains --check` | 0 problem(s) across 70 classes |
| `python -m wks.project --check` | 0 problem(s) |
| `python -m wks.cli drift-audit` | 0 non-clean of 210 |

## Hunt history test coverage (eval/test_hunt_history.py)

1. test_session_files — PASS
2. test_evidence_encrypt_decrypt — PASS
3. test_no_key_fail_closed — PASS
4. test_sanitize — PASS
5. test_outcome_taxonomy — PASS
6. test_timeline_hypotheses_results — PASS
7. test_search — PASS
8. test_recovery — PASS
9. test_rebuild_index_export — PASS
10. test_candidate_extraction_and_fp — PASS

## CLI verification

- `python -m orch.cli history list` → returns `[]` (empty index, expected) — PASS.
- `python -m orch.cli history search` / show / verify / rebuild-index / export available (see orch/cli.py).

## Security verification

- Raw evidence file contains no plaintext (test asserts "secret raw" absent) — PASS.
- Missing key raises RuntimeError (fail-closed) — PASS.
- Tamper detection via integrity hashes — covered by verify_evidence.

## Status summary

- VERIFIED: hunt session creation, evidence encryption/decryption, fail-closed, sanitization, outcome taxonomy, timeline, search, recovery, index rebuild, export, candidate extraction, FP routing.
- FAILED: none.
- BLOCKED: none.
- NOT RUN: external target testing (explicitly out of scope).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase5_test_results.md