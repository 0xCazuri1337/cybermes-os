# Overnight learning loop — 2026-10-04

## GOAL
Close the widest measured evidence gaps in the WKS corpus overnight, using the
real research executor, with every merged item traceable to a live-verified
quote from two independent publishers.

## CRITERIA (each checkable with a command)
- C1 The loop's own task selector is wired: `wks.store.next_task()` returns a
  task when claimable tasks exist.  how checked: `python -c "from wks import store"`
- C2 At least 8 research tasks execute against live sources.
  how checked: `python -m orch.cli stats` -> agents/executed
- C3 Corpus item count strictly INCREASES (no run that only re-gates).
  how checked: `python -m wks.cli metrics` before/after
- C4 Zero new open conflicts from fabricated evidence.
  how checked: `python -m wks.cli metrics` -> open_conflicts
- C5 `wks.cli selftest` stays green (no gate regression from my edit).
  how checked: `python -m wks.cli selftest`
- C6 Every merged item's quotes verify against the live page.
  how checked: `python -m wks.verify_quotes --class <id>` per touched class

## NOT IN SCOPE
- No active testing, scanning or exploitation of any target.
- No lowering of MIN_PUBLISHER_HOSTS or any gate threshold to buy volume.
- No reporting a number that was not re-derived from the db.

## PRE-LOOP STATE (measured, not assumed)
- items_total 1679 | promoted 1065 (63.43%) | classes 70, mature 52
- items under_review 614 | blocked_on_single_host 189
- sources 808 | publisher hosts 140 | fp_rules 325 | chains 79 | conflicts 0
- ready tasks 18 (11 research classes + 7 stale event rows)

## DEFECT FOUND AND FIXED BEFORE ANY RESEARCH RAN
`wks` selected tasks with `status IN ('todo','doing')` while `orch` owns the
canonical vocabulary (`planned/ready/running/completed`) and MIGRATES the table
into it on every orchestrator open (`orch/store.py:migrate_tasks`). The two
layers therefore could not see each other's tasks: `next_task()` returned None
and `wks.cli tasks` printed "no runnable task" over a table holding 18
claimable rows. A clean, confident, EMPTY report over a full backlog.
- fix: `wks/store.py` (claim_task/finish_task/next_task + normalise_task_status),
  `wks/overnight.py` (select_tasks)
- verified both directions: `eval/test_task_status_vocab_v2.py` 19/19 PASS,
  including the negative controls (a child of a blocked / still-running /
  non-existent dep is still refused) and the original defect reproduced on the
  old filter (old=1 row, new=2 rows).