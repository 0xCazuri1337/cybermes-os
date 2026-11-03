# Phase 5 — Hunt History & Closed-Loop Knowledge Feedback: Audit

## Existing capabilities reused (verified)

- `orch/hunt_exec.py`, `orch/hunting.py`, `orch/surface.py` provide execution + surface discovery (unchanged).
- `orch/authz.py` provides AuthorizationContext (unchanged; every session stores its snapshot).
- `orch/validate.py`, `orch/finalgate.py` provide validation (unchanged).
- `orch/learning_bridge.py`, `orch/researcher.py` provide candidate generation hooks (unchanged).
- WKS `task`/`run` records remain distinct from hunt sessions (no duplicate ownership).
- `wks/unified_ingest.py` is the single ingestion entry point (reused by candidate push).
- `wks/fp.py` workflow reused for false-positive submission.
- `wks/eligibility.py` unchanged.

## New module: `orch/hunt_history.py`

Canonical owner of durable hunt-session history. Provides:
- `HuntSession` dataclass with stable session_id, target, authorization snapshot, scope snapshot, outcome, closed_at, interrupted/recovered flags.
- `HuntHistory` manager: timeline, hypotheses, results, negative_results, dead_ends, findings, evidence (raw/sanitized/manifests), knowledge_candidates.
- Encrypted raw evidence at rest (Fernet via `cryptography`, key from `HUNT_EVIDENCE_KEY`, fail-closed if missing).
- Sanitized evidence (redacts Authorization, Cookie, Set-Cookie, token/password/api_key in headers/query/body).
- SHA256 integrity on raw plaintext + sanitized file + encrypted file.
- Outcome taxonomy: POSITIVE_SIGNAL, NEGATIVE_RESULT, INCONCLUSIVE, EXECUTION_ERROR, BLOCKED, OUT_OF_SCOPE, ABANDONED, FALSE_POSITIVE.
- `extract_candidates()` (origin=HUNT), `push_candidates()` (routes through unified_ingest), `submit_fp()` (routes through wks/fp).
- `is_interrupted()` / `recover()` for crash recovery.
- `search()` over sanitized history.
- `rebuild_index()` (disposable index.json), `export_session()`.
- CLI: `orch.cli history {list,show,search,evidence,verify,rebuild-index,export}`.

## Storage layout

```
hunts/targets/<target_slug>/sessions/<session_id>/
  session.json, authorization.json, timeline.jsonl,
  hypotheses.json, results.json, negative_results.json,
  dead_ends.json, findings.json, knowledge_candidates.json,
  evidence/{raw,sanitized,manifests}/
```

## Database changes

None. Hunt history is filesystem-owned; WKS remains canonical for validated knowledge. No large raw bodies in WKS tables. Candidate submissions enter via `knowledge/incoming/` + `unified_ingest`.

## Baseline tests

- `python eval/test_hunt_history.py`: 10 tests, OK.
- `python -m wks.cli selftest`: PASS.
- `python eval/test_wks.py`: PASS.
- `python eval/test_eligibility.py`: PASS.
- `python eval/test_unified_ingest.py`: PASS.
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase5_hunt_history_audit.md