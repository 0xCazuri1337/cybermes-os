# Phase 2 Integrity Report

## Generated file header
- Applied to DIGEST.md via `pipeline.markdown_report` (marker prepended).
- Applied to SKILL.md via `skillgen._HEADER` (marker added to generated comment).
- Exact marker: `<!-- GENERATED from db/wks.db — do not edit -->`

## Projection manifest
- IMPLEMENTED (additive). Table `projection_manifest` with PK (class_id, artifact_type).
  Columns: class_id, artifact_type, relative_path, source_digest, content_sha256,
  generator_version, generated_at. Migration in wks/migrate.py conventions via
  wks/manifest.py ensure_table(). No data loss; existing records untouched.
- Populated with 210 rows (70 classes × 3 artifacts).
- CLI: `python -m wks.cli manifest [--class <id>]`.
- Module: wks/manifest.py with ensure_table, upsert, get, list_for_class, all_rows.

## Drift detection
- Existing `wks.project.drift()` covers: stale, absent, orphan, unmapped, render_error.
- Verified: `skills drift: 0 problem(s)` after migration.

## Rebuild reproducibility
- `wks.cli skills-sync --apply` regenerated 70 classes; idempotent (changed: nothing on re-run).

## Safe generation / rollback
- Not implemented beyond existing idempotent write. Staged generation + rollback deferred.

## Follow-ups
1. Implement projection manifest table + migration (additive).
2. Implement deterministic source_digest (separate from content hash).
3. Implement staged generation with rollback.
4. Fix pre-existing `wks/ingest.py` IndentationError (line 132).
5. Update remaining hardcoded `domains/` references in tools/* (one-off scripts).
6. Flatten assessment/? kept as subdir per mission target (assessment/COMPETENCY.md).
EOF