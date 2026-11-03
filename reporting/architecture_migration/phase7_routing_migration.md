# Phase 7 — Routing Migration

## Changes implemented

- New module `wks/routing.py`.
- Additive schema: `routing_decision`, `route` tables.
- CLI routing subcommand in `wks/cli.py`.
- `eval/test_routing.py` (74 scenarios).
- AGENTS.md update BLOCKED (protected file) — recorded as blocker.

## Files created/modified

- `wks/routing.py` (new)
- `wks/cli.py` (routing subcommand)
- `eval/test_routing.py` (new)
- `reporting/architecture_migration/phase7_*.md` + `final_architecture_report.md` (new)

## Integration

- KNOWLEDGE routes through `wks/unified_ingest.py` + quality gate.
- ATTACK_CHAIN routes through `wks/chains.py` validation.
- FP_RULE routes through `wks/fp.py`.
- SKILL_PROCEDURE remains approval-gated (never auto-activated).
- Dedup integration: routing cannot approve Merge Proposals.
- Hunt history candidates route through central router.

## Rollback

Drop `routing_decision` and `route` tables (additive). Remove routing subcommand. No canonical data affected.

## Blocker

- AGENTS.md write denied by protected-file guard. Routing documentation in AGENTS.md NOT updated. Recorded as BLOCKED. All other deliverables complete.
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase7_routing_migration.md