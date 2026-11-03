# Phase 4 — Knowledge Projection Filtering & Retrieval Governance: Audit

## 1. Existing retrieval architecture (pre-Phase 4)

- `wks/retrieval.py` defined `_STATE_PRIOR` multipliers applied to BM25 relevance. Trust prior was a *multiplier*, not a filter: an `under_review` item with a high prior could still outrank evidenced knowledge in blended score.
- `retrieve()` accepted an optional `states` filter, but the default was `None` → no filtering at all. Every active item (including rejected) was reachable in authoritative context.
- `class_digest()` returned all active items for a class regardless of validation state.
- `skillgen.py` / `methodgen.py` filtered on `validation_state IN ('supported','high_confidence')` at SQL level, but inconsistently and with no shared policy, no open-conflict check, no provenance check.
- FTS5 (`item_fts`) indexed every active item; `_bm25` joined `quality` but did not exclude non-promoted states for authoritative queries.
- No centralized eligibility module existed.

## 2. Actual validation-state enum (verified against db/wks.db)

Only four states exist in the live database:

| State | Count |
|---|---|
| high_confidence | 991 |
| supported | 5 |
| under_review | 557 |
| rejected | 1 |

Open conflicts: 13. Total active items: 1554. Classes: 70.

The mission's eight-state list (discovered, unresolved, disputed, outdated) is **not implemented** in this corpus. Deviation documented: eligibility treats only the four real states; `discovered`/`unresolved`/`disputed`/`outdated` are mapped to the nearest real state or reported as not-applicable. No new states were invented.

## 3. Consumers identified

| Consumer | Path | Pre-Phase-4 behaviour |
|---|---|---|
| FTS5 BM25 | wks/retrieval.py `_bm25` | no state filter |
| Blended rank | wks/retrieval.py `_rank` | prior multiplier only |
| retrieve() | wks/retrieval.py | optional states, default None |
| class_digest() | wks/retrieval.py | all active items |
| skillgen | wks/skillgen.py | SQL filter, no conflict check |
| methodgen | wks/methodgen.py | SQL filter, no conflict check |
| CLI search/show | wks/cli.py | delegates to retrieval |
| ORCH readers | orch/*.py | delegates to retrieval |

## 4. Baseline measurements

- Authoritative-eligible items (supported/high_confidence, no open conflict, ≥1 source): 996.
- Excluded from authoritative: 558 (557 under_review + 1 rejected).
- Open conflicts: 13, affecting 26 items.
- Items missing source links: 0 among promoted.

## 5. Gaps found

- No single eligibility function → duplicated SQL filters with drift risk.
- Trust prior could not be bypassed but also could not *exclude*; multiplier-only.
- Open conflicts were surfaced in output but did not gate authoritative inclusion.
- Empty authoritative retrieval was not distinguished from "no data"; could silently fall back.
- methodgen crashed on `None` body/disproof (latent bug).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase4_retrieval_audit.md