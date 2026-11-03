# Learning/Research Audit

Phase 3 unified ingestion contract implemented.

- Added `origin TEXT` to item table (schema + migration + db).
- Created `wks/unified_ingest.py` with `ingest_candidate`.
- Added `origin` param to `pipeline.ingest_claim`.
- Adapted learning engine update_hook to use unified_ingest with origin=LEARNING.
- AGENTS.md updated.
- Isolated tests pass.
