# Phase 5 — Feedback Loop

## Candidate extraction

- `HuntHistory.extract_candidates()` identifies findings with reusable technical knowledge (those carrying `class_id` + `finding_key`).
- Each candidate carries `origin: "HUNT"` and references the originating session_id, finding, and evidence.
- `push_candidates()` routes candidates through `knowledge/incoming/` and `wks/unified_ingest.py`. No direct promotion.
- Disproof and supporting/contradictory observations preserved when present in the finding.

## False positives

- `HuntHistory.submit_fp()` routes through `wks/fp.py` workflow (existing `fp_case` creation rules).
- Procedure changes require evaluation + approval (existing protection). No automatic SKILL.md modification.

## Promotion restrictions enforced

- ORCH never sets validation_state.
- ORCH never writes directly to SQLite knowledge tables.
- ORCH never modifies CLASS.md/DIGEST.md.
- Candidates that fail the gate remain non-authoritative with proper status/reason.
- Negative/inconclusive results stay in Hunt History; only genuinely reusable, evidence-backed insights become candidates.

## Tests

- test_candidate_extraction_and_fp: PASS (candidate origin=HUNT, FP submission path exercised).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase5_feedback_loop.md