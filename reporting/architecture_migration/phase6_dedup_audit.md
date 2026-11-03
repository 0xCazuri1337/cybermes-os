# Phase 6 — Knowledge Deduplication & Conflict-Safe Consolidation: Audit

## Existing duplicate detection (pre-Phase 6)

- `wks/quality.py` had `dedup_of` / `canonical_id` columns on `item` but no active dedup engine.
- `wks/reconcile.py` and `wks/manifest.py` handled projection reconciliation, not claim deduplication.
- No exact or semantic duplicate detection existed.
- `conflict` table tracked open conflicts but no similarity relationships.
- No merge proposal infrastructure.

## New module: `wks/dedup.py`

- `normalize_text()` — whitespace/punctuation/case normalization preserving negation words (not, never, only, unless, except, before, after, when, without, requires).
- `fingerprint()` — deterministic fingerprint over (class_id, normalized claim, polarity, scope, version, preconditions).
- `polarity()` / `has_negation()` — negation detection.
- `extract_scope()`, `extract_version()`, `extract_preconditions()` — qualifier extraction.
- `semantic_similarity()` — hybrid: SequenceMatcher ratio + token Jaccard + n-gram Jaccard + class-aware boost.
- `classify_relationship()` — returns EXACT_DUPLICATE, SEMANTIC_NEAR_DUPLICATE, COMPLEMENTARY, CONTEXT_DEPENDENT, POTENTIAL_CONTRADICTION, UNRELATED, UNCERTAIN.
- `store_fingerprint()`, `find_exact_duplicates()`, `audit()` — read-only detection.
- `propose()`, `review()`, `apply_proposal()` — proposal lifecycle.
- `mode_dispatch()` — AUDIT/PROPOSE/REVIEW/APPLY modes.
- `authoritative_filter()` — suppresses duplicate presentation in authoritative retrieval.
- `is_duplicate_fp()`, `dedup_candidates()` — FP/hunt integration.

## Schema additions (additive migration)

- `dedup_fingerprint` (item_id PK, fingerprint, normalized_claim, polarity, scope, version, preconditions, method_version).
- `merge_proposal` (proposal_id PK, relationship, item_ids JSON, class_id, similarity_score, signals JSON, proposed_action, status, created_at, reviewer, reviewed_at, decision_reason, applied_at).
- `canonical_group` (group_id PK, canonical_item_id, class_id, created_at).
- `item_group` (item_id, group_id, role) with FKs.

## Contradiction protection

- Positive vs negative assertions under identical scope/version/preconditions → POTENTIAL_CONTRADICTION.
- Different versions/contexts → CONTEXT_DEPENDENT (not contradiction).
- High similarity never overrides contradiction indicator.
- Uncertain relationships → UNCERTAIN (safe default: preserve).

## Baseline metrics

- Total items: 1554 (996 eligible, 558 excluded).
- Open conflicts: 13.
- Exact duplicate groups: measured by audit (see test results).
- Semantic candidate pairs: measured by audit.

## Tests: `eval/test_dedup.py` — 70 scenarios, all PASS.

## Reports

- phase6_dedup_audit.md (this file)
- phase6_dedup_migration.md
- phase6_conflict_analysis.md
- phase6_test_results.md
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase6_dedup_audit.md