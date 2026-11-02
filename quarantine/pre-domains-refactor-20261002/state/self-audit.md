# SELF-AUDIT

health: **degraded**  (19/20 checks passed)


## STRUCTURAL
- [PASS] modules import — 7 modules import
- [PASS] orchestration tables — 11 tables present
- [PASS] graph is acyclic — graph is a DAG
- [PASS] no dangling deps — no dangling deps
- [PASS] CONTROL present — CONTROL complete
- [FAIL] the quality gate is unmodified — gate file(s) modified since baseline: wks/store.py (thresholds unchanged — review before re-baselining)

## FUNCTIONAL
- [PASS] priority engine runs — ranked 0 task(s)
- [PASS] readiness derives from edges — probe resolved to ready
- [PASS] validation returns 6 levels — validation returns a 6-level vector and fails on a missing finding
- [PASS] scope denies by default — unauthorized target denied (no_scope_grant)
- [PASS] knowledge gate still gates — gate re-assessed 530 item(s)
- [PASS] retrieval still retrieves — retrieval rebuilt; 3 hit(s) for 'injection'
- [PASS] metrics still measure — 530 items, 62 classes
- [PASS] checkpoint round-trips — checkpoint round-trips

## BEHAVIOURAL
- [PASS] recursion is bounded — depth budget enforced: depth 1 exceeds __audit_role__ budget 0
- [PASS] independence is enforceable — L4 refuses a self-validating claim
- [PASS] events are idempotent — duplicate signal collapses to one event
- [PASS] stalls are detectable — stall modelled and reported: probe child blocked, 0 of its 2 task(s) runnable, 2 dead-ended
- [PASS] the run can make progress — 0 runnable, 1 in flight — the run can make progress
- [PASS] progress is recorded — 17 run record(s) in the audit trail

## Failures
- **the quality gate is unmodified**: gate file(s) modified since baseline: wks/store.py (thresholds unchanged — review before re-baselining)