# Phase 2 Closure Report — Projection Integrity

## Baseline
- Repository: C:/Users/Administrator/.hermes/cyber (git root, branch main)
- Bug classes: 70 (verified: `SELECT count(*) FROM bug_class` = 70)
- Manifest rows: 210 (70 classes × 3 artifacts: SKILL, DIGEST, CLASS)
- Distinct manifest classes: 70
- Generated artifacts (skills/web + skills/network): 210, all carrying the generated marker.
- Domain tree check: `tree check: 0 problem(s) across 70 classes`
- Projection drift: `skills drift: 0 problem(s)` (210 CLEAN)

## Manifest coverage
- Expected artifact types per class: SKILL.md, DIGEST.md, CLASS.md (3 each).
- Actual manifest rows: 210 = 70 × 3. No missing, no duplicates (PK on (class_id, artifact_type)).
- Manual vs generated: only SKILL.md/DIGEST.md/CLASS.md are generated; HISTORY.md, HUNT.md, topics/, assessment/COMPETENCY.md are either manual or separately generated (COMPETENCY via methodgen, not in manifest yet).
- Header coverage: 210/210 generated artifacts carry `<!-- GENERATED from db/wks.db — do not edit -->`.

## Registry analysis (504 / 62 / 70)
- 504 = total registered skills in runtime/registry.json (capabilities + reporting + workflows + generated class skills + foundation).
- 62 = route keys in the registry (scenario → skill paths).
- 70 = generated class skills under skills/web (61) + skills/network (9), each with stable skill_id (web.<class> / network.<spec>.<class>).
- Each of the 70 classes has exactly one canonical SKILL.md at skills/<domain>/<class>/SKILL.md. No duplicate skill identities remain in the active tree.

## Generated artifact coverage
- SKILL.md: 70, marker present.
- DIGEST.md: 70, marker present.
- CLASS.md: 70, marker present (regenerated via taxonomy_write.py).
- All 210 carry the marker; none are self-referential hashes (hashes live in manifest table only).

## Seven-state drift
- Implemented in wks/project.py: classify(con, class_id, artifact_type) -> one of
  CLEAN, CONTENT_DRIFT, SOURCE_DRIFT, MISSING, UNEXPECTED, GENERATOR_DRIFT, MANIFEST_INCONSISTENCY.
- Read-only audit: `python -m wks.cli drift-audit` (exit 0, 0 non-clean of 210).
- Tests: eval/test_drift_taxonomy.py → 8 passed (all 7 states + CLEAN).

## Staging and rollback
- wks/stage_gen.py: stage() renders into isolated dir (no live/DB writes), validate headers/coverage/hashes; promote() backs up overwritten files, copies, updates manifest, rolls back on failure; recover() cleans partial staging dirs.
- CLI: `python -m wks.cli stage-gen [--stage|--promote DIR|--recover DIR]`.
- Consistency protocol documented in module docstring (no DB/filesystem atomicity claimed; idempotent converge).
- Verified: stage+promote round-trip succeeded; drift 0 after.

## Files changed (Phase 2 closure)
- tools/taxonomy/taxonomy_write.py (marker prepend on CLASS.md)
- wks/project.py (classify/audit + drift-audit CLI)
- wks/stage_gen.py (new)
- wks/cli.py (drift-audit, stage-gen subcommands)
- reporting/architecture_migration/phase2_integrity.md (updated)
- reporting/architecture_migration/phase2_closure.md (this file)
- 70 CLASS.md regenerated with marker.

## Database schema changes
- Additive table `projection_manifest` (PK class_id, artifact_type). No existing tables/records altered. 210 rows populated.

## Exact commands and results
- `python -m wks.domains --check` → `tree check: 0 problem(s) across 70 classes`
- `python -m wks.project --check` → `skills drift: 0 problem(s)`
- `python -m wks.cli drift-audit` → `drift-audit: 0 non-clean of 210` (exit 0)
- `python -m pytest eval/test_drift_taxonomy.py -q` → 8 passed
- `python -m wks.cli stage-gen --stage --classes xss` + promote → ok, rolled_back false
- `python -m wks.cli metrics` → exit 0
- `python -m wks.cli manifest` → lists 210 rows

## Unresolved defects
- Pre-existing `wks/ingest.py` IndentationError at line 132 (user-modified file). NOT fixed per scope. Location: wks/ingest.py:132, `if v == "FABRICATED":` with no indented body. Impact: blocks `wks.cli selftest` and `eval/test_wks.py` import.
- Staged generation tests for interrupted/injected-failure rollback are ad-hoc verified only; no committed eval test file yet (recorded as follow-up).
- COMPETENCY.md (assessment/) not yet tracked in projection_manifest (follow-up).

## Status
- VERIFIED: Phase 1 migration, manifest schema, drift taxonomy (all 7 states), staging+promote round-trip, header coverage (210/210), registry consistency.
- FAILED: none new.
- BLOCKED: wks.cli selftest and test_wks.py (pre-existing ingest.py defect, out of scope).
- NOT RUN: full eval/test_wks.py suite (blocked by ingest.py defect).
EOF