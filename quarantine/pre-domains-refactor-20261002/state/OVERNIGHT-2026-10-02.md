# HERMES OVERNIGHT REPORT - 2026-10-02

## Overall state
**Healthy.** Self-audit 18/18 (structural, functional, behavioural).
Corpus integrity `ok`. WKS knowledge gate green. Orchestration 216/216.

## Project completion
The spec's orchestration layer did not exist. It is now built, wired and
tested. The knowledge engine was already working and was NOT regressed.

| Suite                        | Checks | Result |
|------------------------------|--------|--------|
| SPINE (store/dag/scope/val)  | 58     | PASS   |
| ORCHESTRATOR (end-to-end)    | 47     | PASS   |
| ISOLATION (wks/orch writes)  |  9     | PASS   |
| SCHEDULER (cycles + stop)    | 21     | PASS   |
| ABTEST (refusal paths)       | 20     | PASS   |
| CRASH (real os._exit kill)   | 15     | PASS   |
| AUTHORIZATION (gates)        | 19     | PASS   |
| REGRESSION (independent findings) | 27 | PASS  |
| **Total**                    | **216**| **all** |
| WKS gate regression          |   -    | PASS   |

## Major features implemented
`orch/` - 13 modules over the existing database, ~2,700 LOC:
task DAG, priority engine, L1-L6 validation, agent roles with recursion
budget, orchestrator loop, event relevance, 5 workers, scheduler, A/B,
self-audit, CLI (16 subcommands), authorization gate.

## Features verified by EXECUTION (not inspection)
- Readiness derives from edges; cycles detected (13 arrangements) + repaired.
- 40- and 60-thread claim races: exactly one winner every trial, 0 errors.
- Layer separation MEASURED by SQLite write-tracing: the orchestration write
  set contains ZERO knowledge tables.
- Crash recovery: a real `os._exit(9)` kill is recovered; a live agent is
  never stolen.
- Stop condition fires at genuinely empty state and refuses to fire early.
- Authorization: DESTRUCTIVE blocked without a grant, then without a scope,
  then without offensive permission.
- Idempotency: 0 events left `new`; knowledge tables stable across repeats.

## Knowledge added (delegated research agent)
| metric                        | before | after |
|-------------------------------|--------|-------|
| items                         | 158    | 196   |
| sources                       | 166    | 185   |
| publisher hosts               | 27     | 32    |
| classes mature                | 1      | 8     |
| false-positive rules          | 6      | 58    |
| NETWORK evidenced items       | 0      | 27    |

`domain-health` now reads network declared=25 items=27, closing the invariant
I11 "taxonomy without evidence" violation. Promotion 100%, disproof 100%,
open conflicts 0.

## Architecture changes
`wks/` and `orch/` are now TWO OWNERS OF ONE DATABASE FILE: wks writes
knowledge, orch writes work. Neither writes the other's tables.

## Independent validation (the most important section)
A second agent, given the code but NOT my test suite, tried to break it and
**reproduced 14 defects by execution while all 105 of my own checks were
green**. Every CRITICAL and HIGH item is now fixed and guarded by
`eval/test_regressions.py`. The lesson is recorded in CONTROL invariants
I14-I19: a suite written by the same agent that wrote the code is not
validation.

Fixed from that review:
- `blocked` was TERMINAL — a failed dependency poisoned its dependents forever
  even after repair (I16).
- `check_scope("")`, `check_scope("%")` and any PREFIX of a granted host all
  returned authorized=True (I17).
- L4 passed vacuously with no claimant, reaching verdict=validated with no
  independent agent; independence now also requires different ROLES (I18).
- A malformed expires_at read as "never expires" (I17).
- The stall check returned True unconditionally, so a 100% stalled graph
  audited healthy 18/18; there is now a real progress check (I19).

The validator ALSO verified as sound: find_cycles across 13 arrangements,
store.claim under 40/60-thread races, wks isolation (only quality.assessed_at
ever changes — I4 intact), full idempotency, deterministic priority ranking,
and the recursion guard.

## Known failures / incidents (all fixed)
1. **Fabricated completion** - a default `{"ok": True}` executor marked 12
   research tasks complete producing no knowledge; the report read "executed
   12 task(s)". Reverted; no default executor now exists; `--demo` requires
   `--sandbox` (proven by before/after row counts).
2. **Unrecoverable stall (CRITICAL)** - a hard kill left task AND agent_run
   both `running`; liveness judged from the row recovered 0 tasks, forever.
   Now time-bounded (`stale_after_s`).
3. **Self-blocking loop** - the auditor emitted an untriaged event per cycle,
   so `open_events` grew forever and the stop condition could never fire.
4. **Authorization was decoration (CRITICAL)** - `check_scope` was called from
   no execution path; `capability_grant` had no writer; `apply_validation`
   trusted the caller's verdict string.
5. **Concurrent corruption** - `wks/resolver.py` was overwritten mid-run by a
   writer outside this session (mtime 4.6s before detection), leaving an
   IndentationError that broke the WKS gate. Restored from the verified
   snapshot; the broken copy is archived under CONTROL/superseded/.

## Backups / rollbacks
- tree : E:/bugbounty/cyber-backups/cyber-pre-orch-20261002T034838Z.tar.gz
- db   : E:/bugbounty/cyber-backups/orch-pre-20261002T034838Z.db
         (VACUUM INTO, VERIFIED BY ROW COUNT, sha256[:16]=1ccc504117175cfd)
- note : ROLLBACK-orch-20261002T034838Z.txt (exact restore commands)

## Benchmark results
`exp.priority.gap_vs_unblock` - rank agreement (Kendall tau) against the
class-health reference on the live backlog:
- `unblock_only` **1.0000**
- `gap_weighted` 0.6444   (delta 0.3556)

An earlier version measured a metric both arms satisfied identically
(1.0 vs 1.0) and still declared a winner on delta 0.0000. The metric was
replaced with one that can actually differ, which is what surfaced this
result.

## Resource notes
No external dependencies. Python 3.14 stdlib only, SQLite + FTS5. 60-thread
claim races produced no lock contention failures.

## Remaining TODO
1. NETWORK: 27 evidenced items against 25 classes - still the thinnest
   domain; needs ~12 promoted items + fp rules per class to reach mature.
2. FP rules jumped 6 -> 58; confirm these are genuine lessons, not bulk.
3. Lower-severity findings from the adversarial review are un-triaged.
4. `capability_grant` may hold seeded test grants needing pruning.
5. Memory at ceiling (8,629/8,800) - needs consolidation.

## Recommended next autonomous tasks
1. Re-audit and let the priority engine rank with the winning policy.
2. Continue NETWORK evidence toward class maturity.
3. Wire `orch` scheduling to a real trigger (currently manual invocation).
4. Triage the remaining adversarial findings.
