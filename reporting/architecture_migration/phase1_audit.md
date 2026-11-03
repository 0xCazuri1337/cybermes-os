# Phase 1 Architecture Migration — Audit

## Repository
- Root: `C:/Users/Administrator/.hermes/cyber` (git root, branch main)
- Backup: `E:/bugbounty/cyber-backups/cyber-pre-migration-20261103-005620.tar.gz` (119M)
- DB backup: `E:/bugbounty/cyber-backups/wks-pre-migration-20261103-005850.db` (14M)

## Baseline
- Bug classes: 70 (verified via `SELECT count(*) FROM bug_class`)
- Domains tree check (pre): `tree check: 0 problem(s) across 70 classes`
- Uncommitted user changes present (46 entries) — preserved, not overwritten.

## Pre-migration layout
- Per-class artifacts lived under `domains/<domain>/<class>/` with subdirs:
  `knowledge/` (CLASS.md, DIGEST.md), `skills/` (SKILL.md, HISTORY.md, HUNT.md),
  `assessment/`, `topics/`, `chains/`.
- Shared reusable skills lived under `skills/capabilities/`, `skills/*.md`.

## Post-migration layout
- Per-class artifacts now under `skills/web/<class>/` and `skills/network/<spec>/<class>/`
  with flattened top-level files: CLASS.md, DIGEST.md, SKILL.md, HISTORY.md, HUNT.md.
- Subdirs retained: `assessment/`, `topics/` (and any chains/mastery/labs).
- Legacy original preserved at `superseded/domains-legacy-20261103/`.
- `domains/` directory removed from active tree.

## Consumers updated
- `wks/domains.py`: DOMAINS_DIRNAME = "skills"; CLASS_SUBDIRS flattened
  (knowledge/skills resolve to class dir); `--check` path updated.
- `wks/project.py`: _PROJECTIONS flattened; drift uses class_dir for root artifacts.
- `wks/pipeline.py`: DIGEST.md written to class root; generated marker prepended.
- `wks/skillgen.py`: DIGEST relative link updated; generated marker added.
- `eval/test_learning_hooks.py`: hardcoded path updated.
- `scripts/skill_registry.py`: routing condition + generated flag updated.
- `tools/taxonomy/taxonomy_write.py`: DOMAINS constant updated.
- `wks/cli.py`: help text updated.
- `runtime/registry.json`: regenerated (504 skills, 62 routes).

## Verification
- `python -m wks.domains --check` → `tree check: 0 problem(s) across 70 classes`
- `python -m wks.project --check` → `skills drift: 0 problem(s)`
- `eval/test_domains.py` → 66 pass, 0 fail
- `eval/test_p0_skill_registry.py` → ALL P0-B SKILL REGISTRY CHECKS PASS
- `python -m wks.cli metrics` → OK
- `python -m wks.cli probe` → OK

## Known blockers (pre-existing, unrelated to migration)
- `wks/ingest.py` has an IndentationError at line 132 (in user's modified version).
  This breaks `wks.cli selftest` and `eval/test_wks.py` import. Not caused by migration.
  Recorded as follow-up; not fixed per scope control.
EOF
echo done