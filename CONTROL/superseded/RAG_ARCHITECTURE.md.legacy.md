# RAG ARCHITECTURE

```
Canonical knowledge (knowledge_engine)
        ↓
  rag_engine.py    TrustLevel · ProvenanceState · RetrievalCandidate
                  multi-mode retrieval (memory/knowledge/research)
                  _assess_trust → _filter_candidates → _rerank_candidates
        ↓
  construct_decision_context() → Hermes
```

**Reused, not rebuilt.** `rag_engine.py` (29KB) already provides the hybrid
candidate path, trust assessment, filtering, reranking, decision-context
composition and retrieval-failure recording.

Requirements status: hybrid retrieval ✓ (existing) · trust-aware filtering ✓ ·
progressive disclosure ✓ (`construct_decision_context`) · context budgeting
partial (§20) · deduplication ✓ (`_dedupe_by_content`) · metadata filtering ✓ ·
relationship-aware retrieval ✗ · retrieval telemetry ✓ (write-side not wired
into the loop) · feedback from assessments ✗ · rebuildability ✓ (derives from
canonical knowledge).

Gaps are recorded rather than papered over. A relationship/graph index is not
present; the schema for it is in the taxonomy, not the engine.
