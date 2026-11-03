# Phase 1 Migration Report

## What changed
- On-disk root moved from `domains/` to `skills/` (merged with existing `skills/`).
- Per-class artifacts flattened: `knowledge/CLASS.md`→`CLASS.md`, `knowledge/DIGEST.md`→`DIGEST.md`,
  `skills/SKILL.md`→`SKILL.md`, `skills/HISTORY.md`→`HISTORY.md`.
- 70 class directories migrated; 70 CLASS.md, 70 DIGEST.md, 70 SKILL.md present.
- Legacy original preserved at `superseded/domains-legacy-20261103/`.

## Files modified (code)
- wks/domains.py, wks/project.py, wks/pipeline.py, wks/skillgen.py, wks/cli.py
- eval/test_learning_hooks.py
- scripts/skill_registry.py
- tools/taxonomy/taxonomy_write.py

## Files created
- reporting/architecture_migration/phase1_audit.md
- reporting/architecture_migration/phase1_migration.md
- reporting/architecture_migration/phase2_integrity.md

## Database changes
- None in Phase 1 (no schema changes).

## Test results
- domains --check: 0 problems
- project --check: 0 problems
- test_domains.py: 66 pass, 0 fail
- test_p0_skill_registry.py: PASS
- metrics/probe: OK
- selftest: BLOCKED by pre-existing ingest.py IndentationError (unrelated)
EOF