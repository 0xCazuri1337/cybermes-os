# Phase 6 — Test Results

## Test commands and results

| Command | Result |
|---|---|
| `python eval/test_dedup.py` | PASS (70 tests, OK) |
| `python eval/test_wks.py` | PASS (ALL WKS GATE TESTS PASS) |
| `python eval/test_eligibility.py` | PASS (ALL ELIGIBILITY TESTS PASSED) |
| `python eval/test_unified_ingest.py` | PASS |
| `python eval/test_hunt_history.py` | PASS (OK) |
| `python -m wks.cli selftest` | PASS (ALL WKS GATE TESTS PASS) |
| `python -m wks.domains --check` | 0 problem(s) across 70 classes |
| `python -m wks.project --check` | 0 problem(s) |
| `python -m wks.cli drift-audit` | 0 non-clean of 210 |

## Dedup test coverage (eval/test_dedup.py) — 70 scenarios

- Exact matching (9): identical, whitespace, formatting, punctuation, different class, different conditions, negation, version, scope — PASS
- Semantic similarity (7): equivalent wording, different terminology, complementary, different meaning, threshold boundaries, FTS5 discovery, lexical false positives, uncertainty — PASS
- Contradictions (8): positive vs negative, opposing under identical conditions, different versions, conditional success, auth context, conflicting disproof, uncertainty preservation, high-similarity contradiction not merged — PASS
- Merge proposal workflow (11): exact proposal, semantic proposal, pending no-op, rejected preserved, deferred preserved, human approval required, no self-approval, approved consolidation, duplicate suppression, apply rollback, idempotency — PASS
- Data integrity (13): item IDs, source relationships, publisher refs, quotations, disproofs, origins, validation states, no unauthorized promotion, ineligible exclusion, investigation access, conflict records, FK validity, audit history — PASS
- Retrieval and projections (10): duplicate suppression, complementary visible, context-dependent separate, contradictory separate, CLASS.md, DIGEST.md, FTS5 consistency, manifest, drift, eligibility regression — PASS
- Existing system regression (6): selftest, test_wks, test_eligibility, test_unified_ingest, test_hunt_history, domain checks, projection checks, ORCH auth, mastery — PASS

## Status summary

- VERIFIED: dedup engine, exact + semantic detection, contradiction protection, proposal workflow, safe consolidation, retrieval integration, all regression tests.
- FAILED: none.
- BLOCKED: none.
- NOT RUN: external target testing (out of scope).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase6_test_results.md