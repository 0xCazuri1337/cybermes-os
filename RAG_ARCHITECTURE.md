# RAG ARCHITECTURE

> **Rewritten 2026-10-02.** The previous version described a `rag_engine.py`
> (29KB) and a `knowledge_engine` canonical store. Neither exists: both were
> removed in the Selection-C rework, replaced by the `db/wks.db` + `wks/`
> engine documented in [`README.md`](README.md). Nothing imported this file and
> no module matched it, so it asserted an architecture that had been gone for
> months. The historical text is preserved at
> [`CONTROL/superseded/RAG_ARCHITECTURE.md.legacy.md`](CONTROL/superseded/RAG_ARCHITECTURE.md.legacy.md).

## What actually runs

```
delegated research (subagents)
        ↓  one file per specialist, under research/incoming/
wks/ingest.py        shape → LIVE quote check → gate → db
        ↓
db/wks.db            SQLite + FTS5. The single source of truth.
        ↓                      ↓
projections                    retrieval
classes/*.md                    wks/retrieval.py
chains/*.md                      BM25 (FTS5) + trust prior
skills/<id>-hunting/             + metadata filters
bug-classes/**                   + chain expansion
methodology/derived/
```

## The four components that replaced it

| Was | Is now | Where |
|---|---|---|
| `knowledge_engine` (canonical store) | `db/wks.db` — SQLite + FTS5, no other store | `wks/store.py`, `wks/schema.sql` |
| `rag_engine._assess_trust` | validation-state prior blended into ranking | `wks/retrieval.py`, `_STATE_PRIOR` |
| `rag_engine._filter_candidates` | metadata filters on `item.class_id` / `kind` | `wks/retrieval.py` |
| `rag_engine.construct_decision_context` | `retrieve()` returns claim **with** provenance | `wks/retrieval.py` |
| — (new) | trust-prior ranking, so a 60-char stub cannot outrank a 400-char evidenced claim | rule R7 |

## Requirement status

| Requirement | State |
|---|---|
| lexical retrieval (BM25/FTS5) | ✓ |
| trust-aware ranking | ✓ `_STATE_PRIOR` |
| provenance always returned | ✓ invariant I2 |
| metadata filtering | ✓ |
| deduplication | ✓ `evalm` reports `duplicate_claim_groups` |
| relationship / graph index | ✗ chains are rows + `chain_step`, not a traversed graph |
| semantic retrieval | ✗ **no embeddings are installable on this host** |
| staleness re-review | ✗ `outdated` is a state the system can hold but does not apply |

## The honest limitation

Retrieval is **lexical**. A paraphrase sharing no vocabulary will not match,
and there is no semantic fallback to catch it. That is a real ceiling, not a
rounding error, and `wks.cli probe` measures it: 7 of 8 relevance probes return
the intended top hit. The failing probe is `csrf`, a registered class with
zero gated items — it surfaces an XSS item instead. That is the gap being
reported honestly rather than hidden, which is invariant I9.

Every gap above is stated rather than papered over. A retrieval architecture
that documents only what it does is worse than one with no documentation.