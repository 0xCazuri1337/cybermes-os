# Phase 7 — Test Results

## Test commands and results

| Command | Result |
|---|---|
| `python eval/test_routing.py` | PASS (74 tests, OK) |
| `python eval/test_wks.py` | PASS (ALL WKS GATE TESTS PASS) |
| `python eval/test_dedup.py` | PASS (70 tests, OK) |
| `python eval/test_hunt_history.py` | PASS (OK) |
| `python eval/test_eligibility.py` | PASS (ALL ELIGIBILITY TESTS PASSED) |
| `python eval/test_unified_ingest.py` | PASS |
| `python -m wks.cli selftest` | PASS (ALL WKS GATE TESTS PASS) |
| `python -m wks.domains --check` | 0 problem(s) across 70 classes |
| `python -m wks.project --check` | 0 problem(s) |
| `python -m wks.cli drift-audit` | 0 non-clean of 210 |

## Routing test coverage (eval/test_routing.py) — 74 scenarios

- Deterministic classification (10): clear knowledge, attack chain, FP rule, skill procedure, NO_CHANGE, conflict, unknown type, missing class_id, missing evidence, conflicting rules — PASS
- Hybrid AI routing (10): agree, disagree, multiple routes, invents unsupported kind, forbidden promotion, no evidence, provider unavailable, low confidence, malformed output, prompt injection — PASS
- Two-stage routing (8): preliminary creation, final after promotion, rejected by gate, under review, preliminary changes, final differs, preliminary audit preserved, no preliminary artifact changes — PASS
- Multi-label (6): multiple valid routes, knowledge succeeds while procedure awaits, chain fails while knowledge succeeds, FP independently blocked, aggregate partial, independent retries — PASS
- Execution policies (9): knowledge cannot bypass gate, chain cannot use ineligible, FP requires validation, procedure approval-gated, NO_CHANGE no mutation, CONFLICT preserves both, UNROUTED blocks, explicit approval required, eval failure preserves old procedure — PASS
- Audit and idempotency (12): every decision recorded, NO_CHANGE recorded, UNROUTED recorded, CONFLICT recorded, AI alternatives recorded, reasons/evidence retained, before/after hashes, repeated preliminary idempotent, repeated final idempotent, no duplicate artifacts, failed routes auditable, rollback recorded — PASS
- Dedup integration (6): exact duplicate recognition, semantic proposal reference, pending blocks presentation, approved reflected, contradictory routes to CONFLICT, routing cannot approve merge proposal — PASS
- Existing system regression (13): selftest, test_wks, test_eligibility, test_unified_ingest, test_dedup, test_hunt_history, skill registry, 70 domain checks, projection checks, drift audit, mastery/assessment, ORCH auth, procedure eval — PASS

## Status summary

- VERIFIED: routing engine, two-stage lifecycle, multi-label, hybrid AI, guarded execution, idempotency, audit trail, CLI, all regression tests.
- FAILED: none.
- BLOCKED: AGENTS.md update (protected-file guard). Recorded; not retried per guard instruction.
- NOT RUN: external target testing (out of scope).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase7_routing_test_results.md