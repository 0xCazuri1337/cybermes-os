# Phase 7 — Intelligent Update Routing & Change Governance: Audit

## Existing routing implementations (pre-Phase 7)

- No central routing authority existed. Update kinds were referenced ad hoc in various modules.
- `wks/quality.py` handled promotion; `wks/pipeline.py` handled ingest; `wks/chains.py` handled chains; `wks/fp.py` handled FP rules. Each was invoked independently by callers.
- `wks/unified_ingest.py` was the single ingestion entry point but did not route to multiple destinations.
- No preliminary/final two-stage routing.
- No UNROUTED or NO_CHANGE classification.
- No multi-label routing.
- No routing audit trail.

## New module: `wks/routing.py`

- Update-kind registry: KNOWLEDGE, ATTACK_CHAIN, FP_RULE, SKILL_PROCEDURE, NO_CHANGE, CONFLICT, UNROUTED.
- Deterministic rules engine: versioned, inspectable, human-readable reasons.
- Hybrid AI advisory classification: mockable, never authorizes.
- Two-stage: `preliminary_route(candidate_id)` + `finalize_route(candidate_id)`.
- Multi-label: multiple independent routes per candidate, each with own execution state.
- Routing audit trail: `routing_decision` + `route` tables (append-only, before/after hashes, reasons, alternatives, confidence).
- Routing state model: stage (PRELIMINARY/FINAL), decision result (ROUTED/NO_CHANGE/UNROUTED/CONFLICT/POLICY_BLOCKED), execution (NOT_STARTED/PENDING/AWAITING_APPROVAL/RUNNING/APPLIED/FAILED/ROLLED_BACK/REJECTED).
- Guarded execution: KNOWLEDGE via WKS gate; ATTACK_CHAIN via chain validation; FP_RULE via fp validation; SKILL_PROCEDURE approval-gated (never auto-activate); NO_CHANGE/CONFLICT/UNROUTED no mutation.
- Idempotency: stable candidate-to-route identity; repeated routing detected and not re-executed.

## Database changes

- Additive: `routing_decision` (decision_id PK, candidate_id, stage, selected_kinds JSON, alternative_kinds JSON, decision_result, confidence, reasons JSON, missing_evidence JSON, conflict_refs JSON, dedup_refs JSON, rules_version, ai_suggestion_ref, created_at, updated_at).
- Additive: `route` (route_id PK, decision_id FK, candidate_id, update_kind, destination, preconditions JSON, gate_status, execution_status, review_required, result_refs JSON, before_hash, after_hash, approval_ref, actor, created_at, updated_at).

## CLI

- `wks.cli routing {audit, preliminary, finalize, show, history, pending, unrouted, conflicts, review, execute, metrics}`.

## AGENTS.md

- Write BLOCKED by protected-file guard. NOT updated. Recorded as blocker. See phase7_routing_migration.md.

## Tests: `eval/test_routing.py` — 74 scenarios, all PASS.

## Reports

- phase7_routing_audit.md (this file)
- phase7_routing_migration.md
- phase7_routing_policy.md
- phase7_routing_test_results.md
- final_architecture_report.md
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase7_routing_audit.md