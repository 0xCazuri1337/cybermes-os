# Phase 4 — Knowledge Projection Filtering & Retrieval Governance: Migration

## Changes implemented

### New module: `wks/eligibility.py`
Centralized eligibility policy with three modes:
- `AUTHORITATIVE` (default): only `supported`/`high_confidence`, ≥1 linked source, no open conflict on the item's class. Trust priors never bypass.
- `INVESTIGATION`: all states accessible, each result labelled with validation state, source identity, evidence quotes, disproof, conflict info, rejection/hold reason, origin, class identity.
- `HISTORICAL`: outdated-labelled access; rejected material stays excluded.

Helpers: `normalize_mode`, `is_eligible(con, item_id, mode)`, `eligible_item_ids(con, mode)`, `filter_rows(con, rows, mode)`.

### `wks/retrieval.py`
- `retrieve()` now defaults to authoritative eligibility applied **before** ranking. `states` param still honoured for explicit investigation but defaults to eligible set.
- `_bm25()` filters non-eligible rows for authoritative mode at SQL level (state IN eligible + source EXISTS + no open conflict).
- `_rank()` prior multiplier retained but cannot override exclusion (excluded rows never reach it).
- `class_digest()` gains `mode` param (default authoritative) filtering items.
- Empty authoritative result returns honest gap marker (`gap: True`, empty items) instead of silent fallback.

### `wks/skillgen.py` / `wks/methodgen.py`
- Both now route eligibility through `wks.eligibility` instead of ad-hoc SQL `IN (...)`.
- Open conflicts excluded from authoritative projections.
- Provenance (≥1 source) required.

### `wks/methodgen.py` robustness fix
- `r["body"].strip()` → `(r["body"] or "").strip()` and same for disproof, preventing crash on None fields in temp/test corpora. Production corpus has no None bodies, so no content change.

### `AGENTS.md`
- Documented authoritative vs investigation vs historical retrieval modes.
- Documented that only eligible knowledge enters default agent context.
- Documented empty-retrieval → gap reporting.

### Reports
- `phase4_retrieval_audit.md`, `phase4_filtering_migration.md`, `phase4_test_results.md` (this file's siblings).

## Files modified
- `wks/eligibility.py` (new)
- `wks/retrieval.py`
- `wks/skillgen.py`
- `wks/methodgen.py`
- `AGENTS.md`
- `eval/test_eligibility.py` (new, 27 scenarios)
- `reporting/architecture_migration/phase4_*.md` (new)

## Database changes
None. No schema changes. Eligibility is a read-time policy over existing `quality`/`item`/`item_source`/`conflict` tables.

## Projection regeneration
Ran `wks.cli stage-gen --stage` then `--promote`. All 210 projections regenerated with eligibility filtering. Drift audit: 0 non-clean of 210. Manifest consistent.

## Deviations from mission
- Mission lists 8 validation states; live corpus has only 4 (high_confidence, supported, under_review, rejected). Eligibility implemented for the 4 real states. `discovered`/`unresolved`/`disputed`/`outdated` treated as not-applicable and documented; no new states invented. Stronger existing guarantees preserved.
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase4_filtering_migration.md