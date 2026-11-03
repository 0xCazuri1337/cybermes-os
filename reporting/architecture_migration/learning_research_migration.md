# Learning/Research Migration

Migration steps completed:

1. Schema: `item.origin TEXT` added.
2. `wks/migrate.py`: idempotent ALTER TABLE for origin.
3. `db/wks.db`: migrated (item.origin).
4. `wks/pipeline.py`: `ingest_claim(..., origin=None)`.
5. `wks/store.py`: `add_item(..., origin=None)`.
6. `wks/unified_ingest.py`: new shared ingestion entry point.
7. `learning_engine/engine.py`: update_hook routes through unified_ingest.
8. `AGENTS.md`: routing and shared entry point documented.
