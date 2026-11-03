# Phase 6 — Deduplication Migration

## Changes implemented

- New module `wks/dedup.py`.
- Additive schema migration: `dedup_fingerprint`, `merge_proposal`, `canonical_group`, `item_group` tables (migration versioned).
- `wks/retrieval.py` integrates `authoritative_filter()` to suppress duplicate presentation in authoritative mode.
- `wks/fp.py` integration: `is_duplicate_fp()` prevents redundant FP rule creation.
- `orch/hunt_history.py` candidates deduped via `dedup_candidates()` before submission.
- `eval/test_dedup.py` (70 scenarios).

## Files created/modified

- `wks/dedup.py` (new)
- `wks/retrieval.py` (authoritative_filter integration)
- `wks/fp.py` (duplicate FP detection)
- `orch/hunt_history.py` (candidate dedup)
- `eval/test_dedup.py` (new)
- `reporting/architecture_migration/phase6_*.md` (4 reports)

## Operating modes

- AUDIT: read-only scan, no writes.
- PROPOSE: creates PENDING_REVIEW proposals, no data changes.
- REVIEW: displays proposal details for human decision.
- APPLY: applies approved consolidation only, with rollback.

## Safety guarantees

- No automatic merge.
- No direct validation_state changes.
- No original record deletion (I8).
- No state propagation across grouped items.
- Eligibility evaluated independently per original record.
- Potential contradictions never merged.

## Rollback

Drop the four new tables (additive, no FK to core tables beyond item_id). Revert retrieval integration. No canonical data affected.
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase6_dedup_migration.md