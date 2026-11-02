# Live state (mutable)

This is the only file in `CONTROL/` that changes during a run. The constitution
does not change because a hunt had a bad day.

## Current phase

**Phase 15 — active hunting.** Phase 14 orchestration is unchanged and still green.
The `orch/` hunt layer now enables active testing of external targets when explicitly
authorized. `config.RESEARCH_ONLY` is `True` and `CAN_AUTHORIZE` is `False` in
`wks/config.py` — the WKS layer is research-only and cannot authorize itself.
MEASURED 2026-10-31: this line previously stated `RESEARCH_ONLY = False` and
`CAN_AUTHORIZE = True`. The code was already correct; this was the stale copy of an
earlier configuration, and it contradicted the project constitution and the
research-only boundary. An authorized hunt is started via `python -m orch.cli hunt`
or implicitly when the operator says "start hunt" / "we are hunting" / "begin hunting"
(which triggers `AuthorizationContext` registration with explicit user grant).
The `wks/` layer remains research-only (fetches published docs); active testing
lives in `orch/` and requires explicit user authorization.

| Component | Path | State |
|---|---|---|
| Task DAG | `orch/dag.py` | edges-derived readiness, cycle detection+repair, parallel waves |
| Priority engine | `orch/priority.py` | 7 declared weights, explainable, self-reordering; gap model read from `wks.quality.maturity()` (one source of truth) |
| Validation | `orch/validate.py` | L1–L6; L4 refuses a self-validating claim |
| Agents | `orch/agents.py` | roles as data, recursion budget, claim/validate separation |
| Orchestrator | `orch/orchestrator.py` | decompose → rank → dispatch → gate → checkpoint |
| Events | `orch/events.py` | 4-factor relevance; lead-only ceiling in the scorer |
| Workers | `orch/workers.py` | 5 named workers, heartbeats, crash recorded not swallowed |
| Scheduler | `orch/scheduler.py` | multi-cycle supervision with a real stop condition |
| A/B | `orch/abtest.py` | refuses verdicts the evidence does not support |
| Self-audit | `orch/selfaudit.py` | 21 checks; health = weakest dimension, not an average |
| CLI | `orch/cli.py` | 18 subcommands |

**Verified:** 269 orchestration checks pass across 10 suites, the WKS gate
regression is intact, and the quality gate is fingerprinted (self-audit 20/20).
MEASURED 2026-10-31: the per-suite counts below were re-measured by running
each suite and reading its own result line; several were stale.

MEASURED 2026-11-01: the whole suite was **62/62 files passed**
(`python eval/run_all.py`, 1629s wall clock, 0 failures). The learning-loop
work added `eval/test_p1_writeup_verification.py` (29 checks) and took
`eval/test_cross_workflow_integration.py` from 32 to 43 checks. The
compliance matrix for the learning loop is in "Compliance matrix" below.

MEASURED 2026-11-02: the whole suite is now **65/65 files passed**
(`python eval/run_all.py`, 1094s wall clock, 0 failures). The
provenance-integrity work added `eval/test_p2_provenance_integrity.py`
(8 tests, 40 checks); the compliance matrix for it is in "Compliance
matrix — provenance integrity" below.

| Suite | Checks | Covers |
|---|---|---|
| SPINE | 59 | store/dag/scope/validation |
| ORCHESTRATOR | 49 | end-to-end execution |
| ISOLATION | 9 | wks/orch write separation (measured) |
| SCHEDULER | 21 | cycles + stop condition |
| ABTEST | 20 | refusal paths |
| CRASH | 15 | real os._exit(9) recovery |
| AUTHORIZATION | 20 | capability + scope gates |
| REGRESSION | 27 | defects found by an independent agent |
| EXECUTOR | 32 | the real executor's honesty rules |
| GATE_GUARD | 17 | gate tampering detection (6 files now) |
| DISPATCH REACHABILITY | 18 | a hunt task actually reaches its handler (R3 injects the break) |
| MIGRATION LOCK | 9 | the lock serializes, and never outlives its holder |
| ELIDED QUOTES | 8 | an elided quote is matched by its segments, in order (both directions) |
| CROSS-WORKFLOW INTEGRATION | 43 | hunt -> validated outcome -> verified lesson -> next hunt's decision (A/B controlled) |
| WRITE-UP VERIFICATION | 29 | a sourced write-up reaches the corpus; an unsourced one is held |
| PROVENANCE INTEGRITY | 40 | an origin cannot be self-declared, cannot be edited without an audit record, and every database state opens safely |

MEASURED 2026-10-31: DISPATCH REACHABILITY was new at that point. It had
been FAILING in `eval/run_all.py` (7 pass / 7 fail) while the rest of the
suite reported green — it caught the `can_handle` dispatch regression
(defect 13 below) that nothing else could see. The entry point is
`python eval/run_all.py`, which discovers every `eval/test_*.py` and
reports per-file results.

The system now runs unattended: cron job `cyber-orchestrator-overnight`
(every 3h) drives gate check -> audit -> `run --execute` -> supervise ->
stopcheck, and refuses to proceed if the gate fingerprint has moved.

`orch/` and `wks/` are two owners of one database file, and that separation is
MEASURED, not asserted: `eval/test_isolation.py` traces every write during a
full orchestration workload and asserts the write set contains no knowledge
table. The orchestration write set is
`agent_role, agent_run, checkpoint, event, task, task_dep, worker_heartbeat`.

### Corpus state (MEASURED 2026-10-31)

| Measure | Value |
|---|---|
| items (total / active) | 2086 / 1554 |
| registered classes | 70 |
| classes with >=1 promoted item | 69 |
| maturity split | 44 mature, 26 researching, 0 planned |
| sources | 1100 |
| chains | 79 |
| `fp_case` rows | 88 |
| lessons | 0 published, 51 captured-but-unverified (all test fixtures; all `rejected`, none eligible as experience) |
| findings eligible as impact | 0 of 47 (45 EVAL_TEST, 2 EXAM_FIXTURE) |
| registered skills | 472 |
| open conflicts | 8 (192 raised: 30 resolved, 154 dismissed, 8 open) |
| `RESEARCH_ONLY` / `CAN_AUTHORIZE` | `True` / `False` |

MEASURED 2026-10-31 (R28 citation repair): the source count moved 1099 → 1100
because the repair registered one new Microsoft Learn page
(`win32/dlls/dynamic-link-library-search-order`). The item count is unchanged:
the repair re-pointed 23 citation LINKS, it did not add or remove items.

## Prior phase (superseded — kept for history)

**Phase 13 — canonical taxonomy.** Foundation, gate, retrieval, taxonomy,
seeds, evaluation and the autonomous cycle are built and tested. The db holds
**157 active items** (158 rows, 1 superseded) across **8 of 15** registered
classes, from 89 sources on 12 distinct publisher hosts.

The bug-class taxonomy now exists as a **generated** tree: `bug-classes/`
(**51 canonical class pages**, one 16-section schema, 15 pointer stubs, 6
declared XSS sub-documents), `attack-chains/` (7 files), plus `learning/`,
`validation/` and `reporting/`. It is rendered from
`tools/taxonomy/taxonomy_spec.py` plus the db, so rule 5 (one structure)
and rule 8 (extensible without restructuring) are checkable rather than
aspirational:

```bash
python tools/taxonomy/taxonomy_write.py --check   # drift
python tools/taxonomy/audit_taxonomy.py           # rule 9
```

## Compliance matrix — the learning loop

MEASURED 2026-11-01. Every row names the requirement, the module that owns
it, the public interface, the ACTUAL production caller, what is persisted,
the test that exercises it, and the observed result. A row with no
production caller would be DISCONNECTED, and a row with no observed result
would be UNVERIFIED; neither appears here.

| Requirement | Module | Interface | Production caller | Persists | Test | Observed |
|---|---|---|---|---|---|---|
| Capture a hunt outcome as a lesson | `orch/learning_bridge.py` | `record_hunt_outcome(con, finding_key, lifecycle_state=…)` | `orch/finalgate.py::apply_gate` | `lesson`, `finding_lesson` | `test_learning_bridge.py`, `test_cross_workflow_integration.py` | lesson written with class + provenance |
| Promote a lesson only with evidence | `learning_engine/engine.py` | `verify_hook(con, lesson_key=…, evidence=…)` | `orch/learning_bridge.py:242`, `writeups/pipeline.py:688` | `lesson.state`, `lesson.evidence` | `test_learning_hooks.py` (L4) | no evidence -> refused, stays unverified |
| Reject a false positive from knowledge | `learning_engine/engine.py` | `after_triage(con, lesson_key=…, feedback_type=…)` | `orch/learning_bridge.py:225`, `:404` | `lesson.state='rejected'`, `lesson_feedback` | `test_learning_hooks.py` (L7) | false_positive -> rejected, score down |
| Name what the corpus is missing | `learning_engine/engine.py` | `analyze_hook(con, class_id=…)` | `orch/hunt_cli.py::run_hunt` (hunt close) | `learning_gap` | `test_p1_writeup_verification.py` | gaps persisted; lesson -> `analyzed`, NOT `verified` |
| Turn a gap into a research task | `learning_engine/engine.py` | `research_hook(con, gap_key=…, class_id=…)` | `writeups/pipeline.py::propose_research` | `learning_research`, gap `open`->`proposed` | `test_p1_writeup_verification.py` | 2 gaps -> 2 proposals; 2nd run creates 0 |
| Reach the skill an agent loads | `learning_engine/engine.py` | `update_hook(con, lesson_key=…)` | `orch/learning_bridge.py:267` | `item` (kind `technique`), `item_source`, `quality` | `test_p1_writeup_verification.py` (section E) | item created + cited; quality left `discovered` |
| Read the corpus's prior before recon | `learning_engine/engine.py` | `before_recon(con, target, technologies=…)` | `orch/hunt_exec.py:990` | — (read) | `test_cross_workflow_integration.py` (STEP 8) | prior returned; scope declared `class` |
| Change a decision from the prior | `orch/hunt_exec.py` | `ActiveHuntExecutor._prior_classes`, `_recon_http` | `orch/hunt_exec.py` (recon step) | `finding.priority` | `test_cross_workflow_integration.py` (STEP 9) | A/B: baseline priority != 2, post-lesson == 2 |
| Score a signal against history | `learning_engine/engine.py` | `during_testing(con, signals)` | `orch/hunt_exec.py:462` (`probe_url`) | — (read) | `test_learning_hooks.py` | prior count + average reported |
| Act on the score | `orch/hunt_exec.py` | `probe_differential(...)`, `_prior_from_probes` | `orch/hunt_exec.py` (differential probe) | — (verdict) | `test_p1_learning_loop.py` | `prior` + `recommended_next_step` in the verdict |
| Rank the summary by what was learned | `learning_engine/engine.py` | `before_summary(con, findings)` | `orch/hunt_cli.py:272` | — (read) | `test_p1_learning_loop.py` | findings ranked by verified-lesson score |
| Capture a write-up's lesson | `writeups/pipeline.py` | `extract_lessons(path, con=…, verify=…)` | `writeups/pipeline.py::extract_all_lessons` | `lesson`, `writeup_lesson` | `test_p1_writeup_verification.py`, `test_writeup_pipeline.py` | sourced -> `verified`; unsourced -> held `captured` |
| Run the capture stage | `writeups/pipeline.py` | `all_stages()` | `scripts/update.sh` -> `python -m writeups.pipeline` | — | `test_p1_writeup_verification.py` (F) | capture called BEFORE render (AST-checked) |
| Say where a record came from | `orch/provenance.py` | `classify_from_context(...)`, `normalise(...)` | `orch/store.py::add_finding`, `orch/hunt_exec.py::record_finding`, `writeups/pipeline.py::extract_lessons` | `finding.provenance`, `lesson.origin` | `test_p2_provenance.py` (P1–P4) | origin derived from target/validator_run; defaults fail-closed |
| Refuse test output as experience | `learning_engine/engine.py` | `verify_hook(con, lesson_key=…, evidence=…)` | `orch/learning_bridge.py:298`, `writeups/pipeline.py:695` | `lesson.origin`, `lesson.state` | `test_p2_provenance.py` (P5, P6) | ineligible origin -> refused, stays unverified |
| Return only eligible lessons | `learning_engine/engine.py` | `before_recon`, `before_summary`, `_prior_for_signal` | `orch/hunt_exec.py:990`, `orch/hunt_cli.py:272` | — (read) | `test_p2_provenance.py` (P7–P9) | EVAL_TEST lesson returned to no hunt |
| Count only real impact | `orch/store.py` | `production_impact_count`, `unvalidated_production_count`, `evidence_gap_count` | `orch/scheduler.py::has_useful_work`, `orch/hunting.py` | — (read) | `test_p2_provenance.py` (P10, P11) | test findings count 0; production finding counts 1 |
| Report the corpus's composition | `orch/provenance.py` | `provenance_report(con)`, `audit_provenance(con)` | `orch/selfaudit.py::_f_provenance_is_valid` | — (read) | `test_p2_provenance.py` (P13) | self-audit 21/21; 0 records eligible for impact |

MEASURED 2026-11-01: the provenance work added `eval/test_p2_provenance.py`
(13 tests) and `tools/apply_provenance.py` (the classifier/applier, kept
separate from `tools/reconcile_incident_records.py` so the decision stays
auditable against an artifact).

MEASURED 2026-11-01: the full suite is **62/62 files passed**
(`python eval/run_all.py`, 1629s). The learning-loop work added
`eval/test_p1_writeup_verification.py` (29 checks) and took
`eval/test_cross_workflow_integration.py` from 32 to 43 checks.

## Compliance matrix — provenance integrity (MEASURED 2026-11-02)

The rows above record that a record's origin is DERIVED. They did not
record that the derivation could be OVERRIDDEN: the origin was a claim,
and the claim was enough.

MEASURED 2026-11-02: three defects, each closed by the code below.

1. **SELF-DECLARATION.** `add_finding(provenance="PRODUCTION_HUNT")` and
   `capture_hook(origin="PRODUCTION_HUNT")` accepted the word. The origin
   was the system making a claim about itself.
2. **DERIVATION WITHOUT PROOF.** `classify_from_context` granted
   PRODUCTION_HUNT from a routable target alone, with no authorization
   recorded anywhere.
3. **UNAUDITED MUTATION.** `set_provenance` was the only sanctioned
   correction path, but nothing stopped a raw `UPDATE finding SET
   provenance='PRODUCTION_HUNT'` — so the audit trail recorded the changes
   that went through the function and did nothing about the ones that did
   not.

### The three eligibility distinctions

| Origin | Means | Requires | Counts as impact | Reportable |
|---|---|---|---|---|
| `PRODUCTION_HUNT` | an observation from a hunt the system was authorized to run | a validated `hunt_authorization` receipt naming the hunt AND the target | yes | yes |
| `MANUAL_ENTRY` | a human filed it, outside any hunt | the actor's name | yes | yes |
| `IMPORTED_RESEARCH` | a lesson derived from a published write-up | the source path | no (as a finding) | no (as a finding); yes as experience |
| `EVAL_TEST` / `EXAM_FIXTURE` | the harness's own output | — | no | no |
| `UNKNOWN` | the origin could not be established | — | no | no |

The distinction that matters is between an ORIGIN (where a record came
from) and TRUST (whether it may be used). A record's origin is a fact
about its history; trust is a decision about its use. The origin column
records the first; the eligibility clauses enforce the second.

| Requirement | Module | Interface | Production caller | Persists | Test | Observed |
|---|---|---|---|---|---|---|
| Persist the authorization that permits a hunt | `orch/authz.py` | `AuthorizationContext.validate_and_record(con, hunt_id=…)` | `orch/hunt_cli.py`, `orch/hunt_exec.py` | `hunt_authorization` | `test_p2_provenance_integrity.py` (I1, I2), `test_authorization.py` | receipt written only when the context is complete and the probe is permitted |
| Refuse a self-declared production finding | `orch/store.py` | `add_finding(con, …, provenance=…, hunt_id=…)` | `orch/hunt_exec.py::record_finding`, `orch/learning_bridge.py` | `finding.provenance` | `test_p2_provenance_integrity.py` (I1) | asserted PRODUCTION_HUNT with no receipt -> UNKNOWN, contributes 0 impact |
| Refuse a self-declared production lesson | `learning_engine/engine.py` | `capture_hook(con, …, origin=…, hunt_id=…, authorization_ref=…)` | `orch/hunt_exec.py::_after_finding`, `orch/learning_bridge.py`, `writeups/pipeline.py` | `lesson.origin`, `lesson.provenance` | `test_p2_provenance_integrity.py` (I2) | claim downgraded to UNKNOWN and the downgrade is REPORTED, not silent |
| Check the receipt BEFORE the reserved-name heuristic | `orch/provenance.py` | `classify_from_context(…)` | `orch/store.py`, `orch/hunt_exec.py` | — (read) | `test_p1_learning_loop.py` | a receipt-backed hunt against a reserved name is PRODUCTION_HUNT |
| Refuse a receipt for a different target | `orch/provenance.py` | `authorization_backs(con, hunt_id=…, target=…)` | every creation path | — (read) | `test_p2_provenance_integrity.py` (I3) | a receipt covering another target does not back the record |
| Make the origin immutable in the database | `orch/schema.sql`, `learning_engine/engine.py` | SQLite triggers `trg_finding_origin_immutable`, `trg_lesson_origin_immutable` | every writer | — (guard) | `test_p2_provenance_integrity.py` (I4, I8) | a raw UPDATE is refused by SQLite itself |
| Correct an origin only with an audit record | `orch/provenance.py` | `set_provenance(con, table, key, provenance, reason=…, corrected_by=…)` | `tools/apply_provenance.py` | `provenance_correction` + the origin column, in ONE transaction | `test_p2_provenance_integrity.py` (I5) | the correction succeeds and the audit names old, new, reason and corrector |
| Refuse a promotion without a receipt | `orch/provenance.py` | `set_provenance(…)` | `tools/apply_provenance.py` | — | `test_p2_provenance_integrity.py` (I6) | the promotion raises; the origin is unchanged |
| Demand the receipt at the LAST gate | `learning_engine/engine.py` | `verify_hook(con, lesson_key=…, evidence=…)` | `orch/learning_bridge.py`, `writeups/pipeline.py` | `lesson.state`, `lesson.evidence` | `test_learning_hooks.py` (L4), `test_p2_provenance_integrity.py` (I7) | a production lesson with no receipt cannot be verified |
| Preserve the descriptor through verification | `learning_engine/engine.py` | `verify_hook(…)` | same | `lesson.provenance` | `test_learning_hooks.py` | the descriptor is MERGED with the verification, not replaced — the hunt id survives |
| Exclude an unbacked origin everywhere | `orch/provenance.py` | `impact_clause`, `trusted_lesson_clause`, `promotable_clause` | `orch/scheduler.py`, `orch/hunting.py`, `learning_engine.before_recon` | — (read) | `test_p2_provenance_integrity.py` (I7) | scheduler counts 0; hunt value counts 0; no lesson returned as intelligence |
| Survive every database state | `learning_engine/engine.py`, `orch/store.py` | `ensure_schema(con)`, `open_db(create=…)` | every entry point | — | `test_p2_provenance_integrity.py` (I8) | empty, legacy and partially-migrated databases all open; records preserved; the guard installs |

MEASURED 2026-11-02: the full suite is **65/65 files passed**
(`python eval/run_all.py`, 1094s). The provenance-integrity work added
`eval/test_p2_provenance_integrity.py` (8 tests, 40 checks).

MEASURED 2026-11-02, the canonical corpus, after the closure:
`finding` 47 (45 EVAL_TEST, 2 EXAM_FIXTURE), `lesson` 51 (all EVAL_TEST,
all `rejected`), `hunt_authorization` 0, `provenance_correction` 0.
**Zero records count as production impact**, and the self-audit
(`orch/selfaudit.py::_f_provenance_is_valid`) reports the corpus as
correctly classified. The 47 findings and 51 lessons are RETAINED, not
deleted.

MEASURED 2026-11-02: the skill registry was a PHANTOM. `runtime/registry.json`
advertised 474 skills, but `scripts/skill_registry.py::SKILL_ROOTS` covered
only `domains/` and `skills/`. Regenerating the registry silently dropped
22 skills — including all 17 under `reporting/` (evidence hygiene,
bugcrowd reporting, severity calibration) and the 3 under `workflows/`. The
roots now cover all four directories; `runtime/` and `quarantine/` remain
excluded because they hold BACKUPS. Two entries
(`supporting/misc/testing-mobile-api-authentication`,
`supporting/misc/testing-ransomware-recovery-procedures`) pointed at files
that exist NOWHERE in the tree and were removed as phantoms. The registry
now holds **472 skills, 62 routes**, and `skill_registry.py check` exits 0.

MEASURED 2026-11-02: `tools/backup_snapshot.py` reported `verified: false`
on every snapshot. The count compared the archive's FILE count against the
number of DATABASES, and SQLite's online backup API leaves `-wal`/`-shm`
sidecars beside each copy — so 31 databases became 87 archive members and
the count was off by 56. The check now asserts that every project file and
every database COPY is present, and that the extracted tree matches the
archive. The snapshot `cyber-provenance-integrity-closure-20261102`
(8428 files, 31 databases, all integrity `ok`, all 31 restore-verified)
was complete all along; only the flag was wrong.

MEASURED 2026-11-02: `python -m wks.cli skills-sync --check` reported
`sqli: stale — 45 item(s) on disk differ from render` on all three
projections (skill, knowledge, assessment). The on-disk
`domains/web/sqli/skills/SKILL.md` said `evidence: 1 items ... maturity:
researching` while the corpus holds 45 active items and the renderer
produces `evidence: 45 items ... maturity: mature`. The Oct 29 archive
holds the 45-item file, so the projection had been overwritten with a
degraded render at some point after that — the same foreign-corpus
overwrite `wks.project.assert_canonical_connection` was written to prevent
(the guard is now in place and verified by `wks.cli selftest` T23). The
repair is `python -m wks.cli skills-sync --apply`, after which the check
reports **0 problems** and `tools/audit_architecture.py` reports
`ARCHITECTURE OK`. The corpus in `db/wks.db` was never damaged; only the
PROJECTION was, which is why every database-backed check passed while the
file the agent loads was wrong.

MEASURED 2026-11-02, the two remaining architecture items, verified by
execution rather than by reading:

**Goal orchestration.** `orch/orchestrator.py::decompose(con, goal)` turns a
goal into a dependency-aware task graph — audit -> build -> test ->
validate -> report — plus one evidence-gap task per class the goal names.
It has a production caller (`orch/hunting.py:242`) and a CLI
(`orch/cli.py::cmd_decompose`). Executed against a scratch database: 5
tasks, 4 DAG edges, exactly 1 task `ready` (the first), which is the
dependency order working rather than a list of five independent tasks.

**Five-hook integration.** Every one of the five learning hooks has a real
production caller, and all five were exercised end-to-end through those
callers on a receipt-backed hunt:

| Hook | Production caller | Observed |
|---|---|---|
| `before_recon` | `orch/hunt_exec.py:1063` | the class prior is returned |
| `during_testing` | `orch/hunt_exec.py:462` | 1 signal derived from a 500 + SQL-error response and scored against the prior |
| `after_finding` | `orch/hunt_exec.py:847` | the lesson is captured with origin `PRODUCTION_HUNT` (receipt-backed) |
| `after_triage` | `orch/learning_bridge.py:271` | a `FALSE_POSITIVE` outcome -> the lesson is `rejected`, never promoted |
| `before_summary` | `orch/hunt_cli.py:395` | findings ranked by the verified-lesson prior |

**Write-up pipeline.** `writeups/pipeline.py::all_stages` runs process ->
index -> extract -> render -> research -> briefing, with the capture stage
BEFORE the render stage (rendering first would write a file that omits the
lessons the same run just extracted). Verified by
`eval/test_p1_writeup_pipeline.py`, `eval/test_p1_writeup_verification.py`
and `eval/test_writeup_pipeline.py` — all pass.

## Architecture as built
| Component | Path | State |
|---|---|---|
| Canonical store | `db/wks.db` (SQLite, FTS5) | working |
| Schema | `wks/schema.sql` | 14 tables + FTS + 3 triggers |
| Quality gate | `wks/quality.py` | 10-dimension vector, 17 hard-gate reasons |
| Retrieval | `wks/retrieval.py` | BM25 + trust-prior blending |
| Pipeline | `wks/pipeline.py` | ingest, sanitize, seed verify, markdown |
| Taxonomy spec | `tools/taxonomy/taxonomy_spec.py` | 94 class pages, 15 stubs, 7 chains, 1 sub-doc |
| Coverage | `tools/taxonomy/check_methodology_coverage.py` | reads `bug_class.methodology`; 70/70 covered |
| Metrics | `wks/evalm.py` | 28 metrics, all live |
| Cycle | `wks/cycle.py` | 12-step autonomous loop, bounded by `max_items` |
| Learning engine | `learning_engine/engine.py` | 9 hooks; capture -> analyze -> research -> verify -> update |
| Learning bridge | `orch/learning_bridge.py` | hunt outcome <-> lesson; triage feedback recalibrates score |
| Lesson projection | `learning_engine/engine.py::update_hook` | verified lesson -> `item` (kind `technique`) -> class skill |
| Write-up pipeline | `writeups/pipeline.py` | process -> index -> extract -> render -> research -> briefing |
| Tests | `eval/test_wks.py` | all pass |

MEASURED 2026-10-31: every count in this table was re-read from the code or
from the command's own output. The previous values (12 tables, 4 hard gates,
51 class pages, 15/15 covered, 13 metrics) predated the network taxonomy, the
extra gate rules, and the schema growth.

Dependencies: **none** beyond the Python 3.14 standard library. No embeddings:
none are available on this host, and curated metadata is the better shape for
hunting knowledge anyway.

## Key decisions and why

- **Single SQLite file, no vector store.** FTS5 with BM25 is inspectable: a
  hunter can see which sources back a claim. Cosine similarity over a corpus of
  stubs and evidence cannot.
- **Trust-prior ranking.** Pure BM25 rewards short dense text, so a 60-character
  stub outranked a 400-character evidenced claim. Ranking blends relevance with
  the validation-state prior so weak material is still *reachable* but never
  *dominant*. See rules R7.
- **Hard gates, not just scores.** The previous system let 1,380 unsourced stubs
  reach `validated` because a weighted average can be passed by a fluent,
  short, confident-sounding claim. Host-diversity and fabricated-ref checks are
  *necessary conditions*, not inputs to a mean.
- **Legacy corpus quarantined, not migrated.** 0 of 1,380 records survive the
  current gate. See `runtime/state/legacy-audit.json`.

## Verified defects found and fixed during the build

These are recorded because each was silent and each would have recurred:

1. `config` resolved paths at **import** time, so a sandboxed run reused the
   previous database. Now `config.root()` resolves per call.
2. Gate reasons are stored as `TAG(detail)`. Comparing `"FABRICATED_REFS" in
   reasons` silently failed on `"FABRICATED_REFS(4)"`, and a fabricated-source
   item reached `supported`. Now compared via a tag set.
3. `verify_seed` used HEAD; portswigger.net returns 404 to HEAD on ~20 live
   pages, which would have sent research after phantom dead URLs. Now GET.
4. `gap_report` called `sum()` on an `int` — crashed on every call.
5. `sorted(<genexp>, key=...)` is a `SyntaxError`; generator must be wrapped.
6. `chain_step` has no `chain_key` column; `_chains_for` selected one and
   crashed retrieval on every item that had a chain.

### Found by the 2026-10-02 full audit

7. **Two generators owned the same six paths.** The six XSS variant pages were
   rows in `taxonomy_spec.CLASSES` *and* rendered by `tools/fill_subdocs.py`.
   `taxonomy_write.py` overwrote evidence-backed sub-documents with "Not yet
   researched." skeletons on every run, and `--check` still passed — the
   overwrite *was* the spec. The spec claimed 57 canonical classes while only
   51 ever existed on disk. Fixed: the variants are declared in `SUBDOCS`,
   removed from `CLASSES`, and `taxonomy_write.py` now refuses to write if a
   path is claimed twice.
8. **`audit_taxonomy.py` crashed, so rule R14 was uncheckable.**
   `BUG_SECTIONS.index("How it works")` raised `ValueError` on a sub-document
   heading. A gate that raises reports nothing — indistinguishable from a pass.
   Fixed: sub-docs are excluded from the class-page schema check, the order
   check uses a rank dict that cannot raise, and a declared sub-doc that goes
   missing is now itself a finding.
9. **`check_methodology_coverage.py` could never pass.** It read
   `mastery/competencies.json`, deleted in the Selection-C rework, and exited 1
   on every run while being cited from three READMEs as though it worked. Its
   `COVERED_BY` literal had also drifted (`business_logic` vs the db's
   `bizlogic`; no entry for 9 of 15 classes). Fixed by reading the canonical
   `bug_class` table and **deleting** the literal rather than repairing it.
10. **`bug_class.methodology` stored absolute paths.** All 15 rows embedded one
    user's home directory, so the tree could not be relocated or checked on
    another host. Fixed at the writer (`wks/methodgen.py`) and migrated in
    place; paths are now repo-relative.
11. **The generated hunting skills were unreachable from Hermes.** They are
    written to `cyber/skills/`, while Hermes loads from
    `%LOCALAPPDATA%/hermes/skills/`, and no module read `cyber/skills/` at all
    — eight skills that no routing path could reach. Fix in progress: a bridge
    skill in the Hermes skill tree that dispatches to the canonical store
    rather than copying the projections, which would go stale on the next
    research cycle.
12. **`wks.cli probe` scored a wrong-class hit as a pass.** The `csrf` probe
    returned an XSS item — csrf has zero gated items — and the run still
    reported `hit_rate_pct 87.5`, which reads as reassurance while describing a
    coverage gap. A relevance metric must distinguish "retrieval failed" from
    "we hold no knowledge of this class". Fixed: four verdicts
    (`pass` / `wrong_class` / `weak_state` / `no_knowledge`) and the rate is now
    computed over *testable* probes only. Measured after the fix: 7 tested,
    7 pass, `no_knowledge=1` (csrf) → **100% of what can be tested passes**, and
    the csrf gap is named instead of averaged away.

### Found by the 2026-10-31 full audit

13. **`ActiveHuntExecutor.can_handle` returned False for EVERY key.** The
    dispatch table was gone: the CLI routed a task to the active executor
    only when `can_handle` said yes, and it said no always, so every hunt
    task fell through to the maintenance executor. The symptom was a hunt
    that ran to COMPLETE, exited 0, and gated 14 candidate findings while
    never dispatching a single task to a handler — no trace entry, no
    outcome, no recon. The CLI summary read like a healthy hunt, and the
    only check that could see it (`eval/test_dispatch_reachability.py`)
    had been failing in `eval/run_all.py` while the rest of the suite
    reported green. The method's own docstring describes the capability
    test it was supposed to implement, and R3 of the reachability suite
    injects `return False` by string-matching that exact body — so the
    suite had been asserting the absence of the code it was written to
    guard. Body restored; the suite is now 18/18, and its negative control
    still fires.
14. **A killed process left the migration lock held forever.**
    `wks/migration_lock.py` releases the lock in a `finally`, which a
    SIGKILLed holder never runs. The abandoned row then blocked every
    writer in the project: `MigrationLockTimeout: could not acquire the
    'wks-schema' migration lock` and `sqlite3.OperationalError: database
    is locked`. MEASURED: an interrupted eval suite left `wks-schema` held
    by a dead pid, and the taxonomy generator and the reachability suite
    both failed on it in the same run. The lock table already recorded the
    holder's pid; nothing acted on it. Fixed: a holder whose pid is no
    longer running is reclaimed (reported, never silent), a holder whose
    pid is UNKNOWN is waited out rather than stolen, and `lock_status`
    distinguishes live from stale. Pinned by `eval/test_migration_lock.py`
    (9 checks, both directions).
15. **23 citations were live, real and about something else.** R28's
    subject checkers did not exist, so nothing asked whether a cited page
    was ABOUT the class that cited it. Windows classes
    (`windows_privesc_service`, `windows_privesc_token`,
    `windows_privesc_hijack`) cited Linux man pages, each carrying the man
    page's own text as the quote: `execve(2)`'s resource-limit sentence was
    filed as evidence for the Terminal Services RPC impersonation chain, and
    `ld.so(8)`'s `LD_PRELOAD` variable list as evidence for the Windows DLL
    search order. Repaired by `tools/repair_r28_citations.py` to the
    correct Microsoft Learn page with a quote taken from that page and
    verified against it at repair time. Prior state preserved in
    `superseded/r28-citation-repair-20261031.json`.
16. **The quote verifier could not match an elided quote, so it reported
    genuine evidence as fabricated.** `find_quote` required the WHOLE stored
    quote to appear on the page. A quote carrying an ellipsis — how an agent
    records "the relevant part of a long passage" — could therefore never
    match, and every such citation was reported FABRICATED. MEASURED: 29
    citations in the live corpus carry an ellipsis and all 29 were reported
    as fabricated evidence. That is the worst kind of false positive: it
    tells the operator their evidence is a lie when the evidence is a
    genuine excerpt of a page that says exactly that. Fixed: an elided
    quote is matched on its SEGMENTS, each of which must appear on the page
    IN ORDER, with the leading segment long enough to be distinctive.
    Pinned in both directions by `eval/test_elided_quotes.py` (8 checks).
17. **The corpus's quote fidelity was never measured, because the check
    could not finish.** `wks.verify_quotes` is correct but SEQUENTIAL, and
    it keys its cache on `(url, quote)`, so a page cited by 40 items is
    fetched 40 times. MEASURED: a full-corpus `--json` run exceeded 900s
    and was killed. The honest number was not "there might be some" — it was
    UNKNOWN. `tools/audit_quotes_bulk.py` now fetches each distinct URL once
    and checks every citation against it (922 URLs, 3,418 citations, ~4
    minutes at 12 workers).

    The first honest measurement changed the finding, and that is the
    point. The naive reading is "335 fabricated citations" (9.8%). Measured
    properly, across three independent tools, they are not one thing:

    | Verdict | Count | Share |
    |---|---|---|
    | present on the page (verifier artefacts) | 8 | 2.4% |
    | confirmed in an ARCHIVED copy — the page was rewritten after the citation | 48 | 14.3% |
    | elided excerpt (fixed by defect 16) | 2 | 0.6% |
    | near-verbatim paraphrase (>=90% of the quote's tokens are on the page) | 165 | 49.3% |
    | paraphrase (70-90%) | 66 | 19.7% |
    | loose paraphrase (40-70%) | 71 | 21.2% |
    | mostly absent or absent (15% or less) | 33 | 9.9% |

    So the corpus is **90% sound in claim and imprecise in wording**: 231 of
    the 335 (69%) carry the source's meaning with reworded phrasing, 71
    (21%) are loose, and only 33 (9.9%) are genuinely unsupported. Calling
    all 335 "fabricated" would have been wrong, and would have pushed an
    operator into rewriting a corpus that was never false — the exact
    over-reporting the project's own invariants warn about ("a rejection rate
    from an unvalidated verifier is a measurement of your own bugs").

    The real defect this exposes is not fabrication but a FIDELITY CLAIM the
    corpus does not earn: these citations are stored as verbatim quotes and
    are in fact paraphrases. MEASURED example (OWASP Authentication Cheat
    Sheet): stored — "The failure counter must be associated with the
    account, not the source IP address, for password guessing controls";
    actual page — "The counter of failed logins should be associated with
    the account itself, rather than the source IP address". The meaning
    holds; the words do not.

    This is now REPORTED, not silently repaired: repairing 335 citations is
    a research task with a judgement in each case, and a bulk rewrite that
    invents replacement quotes would manufacture exactly the defect it is
    meant to fix. The tools that measure it are
    `tools/audit_quotes_bulk.py` (fetch once, judge all),
    `tools/classify_quote_drift.py` (live vs archived — is the page stale or
    was the quote invented?) and `tools/quote_fidelity.py` (token coverage —
    is this a paraphrase or an invention?).

### Found by the 2026-11-01 Goal-chain audit

18. **The ownership boundary was enforced only by a TEST.** `wks/store.py`'s
    `open_db` took `owner: str | None = None`, and `None` meant
    UNRESTRICTED. The runtime authorizer in `wks/ownership.py` existed and
    worked, but every WKS connection in the tree opened unrestricted — so
    "ingest-only corpus writes" was a property of the test suite, not of the
    running system. A property only a test enforces is a property the system
    does not have.

    `open_db` now defaults to the WKS owner. A setup path that genuinely
    crosses the boundary says so with `unrestricted=True`, and the crossing
    becomes greppable. MEASURED: a raw `INSERT INTO finding` on a WKS
    connection is now refused with "not authorized", while
    `INSERT INTO bug_class` succeeds.

    The change exposed three writers that had been crossing silently:
    `add_task`, `claim_task` and `finish_task` write the `task` table, which
    is ORCHESTRATION-owned. They are now decorated `@as_owner(ORCH)` — the
    sanctioned-crossing mechanism that already existed for exactly this, so
    the crossing is explicit at the call site instead of the whole connection
    being silently unrestricted.

19. **The FP gate CRASHED on a finding that does not exist.**
    `orch/fp_checklist.run_fp_gate` raised `KeyError("unknown finding …")`,
    and the raise propagated through `orch.finalgate.gate` into
    `orch.omh.qa_finding` — so QA's independence check on a non-existent
    finding crashed its caller instead of refusing the certification. A gate
    that cannot be evaluated must produce a verdict, and the verdict for a
    finding that does not exist is "not reportable". The gate now returns a
    failed verdict (every check fails, `downgrade_to: LEAD`) instead of
    raising.

20. **A test asserted a PROXY and failed while the real property held.**
    `eval/test_wks_integrity_repair.py` checked "no evidence row comes from a
    disqualified or failed exam" by asserting `evidence_count ==
    finding_count`. That proxy is false by construction: a finding with six
    captured request/response pairs contributes six evidence rows and one
    finding row, and a deduplicated finding contributes a finding row and no
    evidence row. MEASURED on the live database: evidence=38, finding=40 —
    the check failed while every evidence row in fact came from an exam with
    `verdict: PASS`. The check now reads each evidence row's provenance and
    asks whether its exam was admissible.

    A proxy that fails when the real property holds trains its reader to
    ignore it. The same fix also had to handle a Windows path recorded on a
    POSIX host: `os.path.dirname` does not split a backslash path, so the
    exam id came out EMPTY and every row was judged against a blank exam
    record. A path written by one platform must be readable by another.

21. **The source registry was TWO registries, not one.** `db/sources.json` is
    the merged artifact built by `tools/build_sources.py` from five seed
    registries, and it is what every briefing, coverage report and worklist
    is built from. But the LIVE research loop
    (`orch/researcher.py::seed_sources`) iterated `wks/taxonomy.py::_SEED`
    in-process and never read the merged file.

    MEASURED: the two were IN SYNC at the URL level (the 50 URLs in `_SEED`
    and the 50 `defined_in: taxonomy._SEED` rows in `db/sources.json` were
    identical), so this was a split source of truth rather than an incorrect
    result — but a curated seed edited in one place would reach the
    researcher and not the briefing. The research loop now reads the merged
    registry, with the corpus-derived `class-seeds.json` as the fallback.
    The registry is a strict SUPERSET of the curated seeds (MEASURED: no
    curated URL is missing from any class; `race`, `graphql` and
    `mass_assign` gain 1, 1 and 2 normative URLs from the extended-web
    taxonomy).

    The check that pins this is BEHAVIOURAL, not a grep of the source: it
    hides `db/sources.json` and proves the loop falls back to the DERIVED
    seeds rather than to a private curated list, and it asserts the probe is
    not vacuous by choosing the class with the most curated-only URLs.
    MEASURED negative control: re-introducing the private-list read makes
    the check FAIL, and removing it makes it pass.

22. **A third seed list existed with no callers.** `extra_seed_sources()`
    in `orch/researcher.py` hard-coded four standards URLs. MEASURED: it had
    no callers anywhere in the tree, and all four URLs are already in
    `db/sources.json` via `wks/taxonomy_ext.CATALOG`. It was removed rather
    than wired up — wiring it up would have created a source of truth that
    bypasses the merged registry.

### Found by the 2026-11-01 ownership audit

23. **Two collection tables were OWNERLESS, so the collection layer was
    broken at runtime.** `collection_waf_status` and `collection_deferral`
    were declared in NEITHER `KNOWLEDGE_TABLES` nor `ORCHESTRATION_TABLES`.
    An ownerless table is writable by NOBODY, so every write to them was
    refused with "not authorized" the moment the ownership authorizer was
    installed by default.

    The feature was broken and the suite was green, because
    `eval/test_collection_dispatch.py` built its sandbox with a bare
    `sqlite3.connect` and never exercised the authorizer at all. That is
    this project's own I33 lesson recurring: a green suite that never opens
    the real connection. The tables are now ORCHESTRATION-owned (they record
    what a collection role measured during a hunt), and the test now opens
    the database the way production does. MEASURED negative control:
    removing the ownership fix makes the test fail with ten errors.

24. **The `evidence` table's corpus-link columns existed in no schema.**
    `evidence.class_id`, `evidence.item_id` and `evidence.exam_id` were
    present in the live database but declared in NO schema file and added by
    NO migration. A FRESH database could not import exam evidence at all:
    `wks.assess_evidence` writes `class_id` and `exam_id`, and the INSERT
    failed with "table evidence has no column named class_id". The import
    was only ever possible on the one database that had been patched by
    hand — which is not a schema, it is a coincidence.

    The columns are now declared in `orch/schema.sql` and
    `orch.store.open_db` migrates existing databases with
    `_migrate_evidence_links`, which is idempotent and preserves every row.
    MEASURED: a fresh database now imports 2 exam findings and 2 evidence
    rows.

25. **The exam-to-evidence import wrote across the boundary without a
    sanction.** `wks.assess_evidence.import_all` wrote `finding` and
    `evidence` — ORCHESTRATION tables — with raw INSERTs and no
    `@as_owner(ORCH)`. On a restricted connection those writes failed with
    "not authorized"; on an unrestricted one they crossed silently. The
    writes are now inside a declared `owner_write(con, ORCH)` block, so the
    crossing is greppable at the call site and every other write on that
    connection is still refused.

26. **A missing finding and a failed validation were indistinguishable.**
    `orch.fp_checklist.run_fp_gate` returned the same shape for "the
    finding does not exist" and "the finding failed the checklist", and
    `orch.omh.qa_finding` returned `ok: True` for both. A caller could not
    tell "the finding was checked and failed" from "there was no finding to
    check", and would have tuned the checklist instead of fixing the lookup.

    The gate now carries `outcome` — `missing_finding`, `failed_validation`,
    `unanswered` or `passed` — and `qa_finding` returns `ok: False` with
    the reason named for a missing finding. MEASURED: an unexpected DATABASE
    error (a missing `evidence` table) still PROPAGATES as
    `sqlite3.OperationalError`; it is never silently converted into a
    validation failure.

27. **The exam-evidence provenance judgement was inline in a test.**
    `eval/test_wks_integrity_repair.py` decided admissibility itself, which
    meant the test and the importer were two representations of the same
    rule and could drift. The judgement now lives in
    `wks.assess_evidence.evidence_admissibility`, and the test calls it.

    MEASURED: the first version of that function decided "is this
    exam-backed?" with a TEXTUAL test (`"grade" not in prov`), which was
    wrong in both directions — a malformed string containing the word
    "grade" was parsed as exam-backed, and a JSON document naming no exam
    was waved through as a live capture. The test is now STRUCTURAL: parse
    first, then ask what the parsed document IS. The two concerns are
    tested INDEPENDENTLY, because they fail differently.

28. **A control rotted as the corpus improved.**
    `tools/test_sourcebook.py`'s publisher-independence control looked for
    a REAL class that was 2-hosts/1-org. When the corpus improved — every
    class now has ≥2 distinct publisher ORGs, because the nine blocked
    NETWORK classes were re-seeded — the control found ZERO thin classes
    and reported FAIL. The detector was fine; the corpus got better. The
    control now CONSTRUCTS the thin class it needs, and the live registry
    is checked as information rather than as a pass/fail condition.

29. **The registry's METADATA was never checked, only its URLs.**
    `tools/check_sources_parity.py` proves the merge loses and invents no
    URLs. It does not prove the merged file still carries what the gate
    reads: the publisher org (the unit `MIN_PUBLISHER_HOSTS` counts), the
    role (the unit that decides whether a source counts at all), the class
    association (what routes a source to a class), and `defined_in` (which
    registry contributed it). A registry that kept the URLs and dropped the
    publisher org would pass every URL-level parity check and quietly
    collapse "two publishers" into "two pages".

    `tools/test_sourcebook.py` now checks all of it, and checks that the
    corpus-derived fallback cannot OVERRIDE a canonical registry entry.
    MEASURED negative control: promoting a lead to `normative` makes the
    check FAIL, and restoring it makes it pass.

### Found by the 2026-11-01 learning-loop audit

30. **The learning workflow's OUTPUT was a dead end.** The write-up
    pipeline captured lessons into the canonical `lesson` table in state
    `captured`, and nothing ever moved them on. Every reader that matters —
    `before_recon`, `before_summary`, `_prior_for_signal` — filters on
    `state='verified'`. So a lesson distilled from a published write-up
    could NEVER influence a hunt. MEASURED on the live database: 48
    lessons, all `captured`, 0 verified, 0 `writeup_lesson` rows, and not
    one processed write-up behind any of them.

    Worse, the capture stage was UNREACHABLE. `writeups/pipeline.py::
    all_stages` ran `write_lessons_markdown()` — which only RENDERS the
    table into `memory/report-lessons.md` — and never called
    `extract_lessons()`, which CAPTURES lessons into that table. The
    function was defined and never called; `grep` for its call sites
    returned only its own `def`. So `/update` regenerated the report from
    whatever was already in the table and added nothing to it.

    A PROCESSED WRITE-UP IS THE EVIDENCE: it is a published account of a
    vulnerability that was found, reproduced and reported. A lesson
    distilled from one is verified on the strength of the write-up itself,
    PROVIDED the write-up names a class and a source URL — an unattributed
    blob has no provenance to verify against and stays `captured`. The
    capture stage now runs BEFORE the render stage, because rendering first
    would write a file that omits the lessons the same run just extracted.
    `eval/test_p1_writeup_verification.py` (29 checks) proves the chain and
    proves the gate still holds.

31. **The projection rendered from the corpus, so a verified lesson never
    reached the skill file.** `learning_engine/engine.py::update_hook` is
    the only path that calls `wks.project.refresh_class`, and it had NO
    production caller. But `wks.skillgen.render` builds the skill from
    `wks.retrieval.class_digest`, which reads the `item` and `fp_case`
    tables — NOT the `lesson` table. So refreshing the projection after a
    lesson was verified re-rendered the skill from the corpus as it already
    stood: the lesson's content never appeared in the file an agent loads,
    and the lesson stopped one step short of the thing it was supposed to
    teach.

    The lesson is now written into the corpus as an `item` — a falsifiable
    claim of kind `technique`, carrying the lesson body — and only then is
    the projection refreshed. The item is created in `discovered` state,
    which is the state `wks.quality` promotes; the learning engine does
    not get to decide that its own lesson is high quality. The source is
    linked when the lesson has one, because a claim with no citation can
    never be promoted. `update_hook` is now called from
    `orch/learning_bridge.py::record_hunt_outcome`.

32. **`during_testing`'s score was computed on every probe and consumed by
    nothing.** The hook was wired into `ActiveHuntExecutor.probe_url` and
    its score was attached to the response as `learning_score` — and no
    decision code read it. The corpus knew how much verified history
    backed a signal and the answer went nowhere.

    The differential probe is the one place where that prior changes what
    to do NEXT: a class the corpus has PROVEN exploitable before is worth
    taking to independent validation, and one it has never seen is worth a
    second look before it is promoted. `probe_differential` now carries the
    prior and a `recommended_next_step`. The prior is ADVICE, never
    evidence: it does not change the `differential_observed` verdict and it
    does not move a confidence band, because a corpus that has been fooled
    before must not be able to promote its own next finding.

33. **The program's verdict never went back to the corpus.**
    `orch/learning_bridge.py::record_triage_feedback` — the function that
    records a program's verdict on a lesson and RECALIBRATES its score —
    had no production caller; only `eval/` called it. The gate decided a
    finding's fate and the corpus never heard about it: the
    `lesson_feedback` table stayed empty, and a lesson the program had
    rejected as a duplicate kept its score.

    `orch/finalgate.py::apply_gate` now records the verdict it just
    derived. The mapping is by the FAILED STAGE, not by the coarse
    verdict, because the verdict only says REPORT_READY or NO_REPORT — it
    does not say WHY. The four corpus feedback types are not
    interchangeable: `duplicate` means the finding was REAL but not novel,
    which is a different lesson from `false_positive`, and conflating them
    teaches the corpus the wrong thing.

34. **`analyze_hook` and `research_hook` had no production caller.** The
    learning workflow's chain stopped at capture: the corpus recorded what
    it learned and never worked out what it was MISSING. MEASURED on the
    live database: `learning_gap` and `learning_research` were both empty.

    The close of a hunt is the right moment to analyze — it is when the
    corpus has just absorbed a batch of new lessons, so it is when the gaps
    are worth naming. `orch/hunt_cli.py::run_hunt` now calls
    `analyze_hook`, which persists the gaps and advances captured lessons
    to `analyzed` (still NOT verified: `before_recon` and `before_summary`
    read only `state='verified'`). The `/update` pipeline now calls
    `research_hook` through `writeups/pipeline.py::propose_research`,
    which turns the open gaps into persisted research tasks and moves the
    gaps `open -> proposed`.

35. **`before_recon` took a `target` it never used.** The argument was
    echoed back in the result next to the lessons, so a reader could
    reasonably conclude the return was target-scoped — while the query
    returned every lesson the corpus held for any target.

    The BEHAVIOUR is right and is kept: a verified lesson is class-level
    experience, and `ActiveHuntExecutor._prior_classes` says why in the
    code — "a class with a verified lesson is a class this system has
    PROVEN exploitable before, so it is worth looking for again".
    Scoping the prior to the host would throw away exactly the
    intelligence the corpus accumulated. What was wrong was the
    REPRESENTATION: a silent corpus-wide read presented as target-scoped.
    The scope is now explicit — `scope: "class"`, each lesson carries its
    own `scope`, and `target_lessons` and `class_lessons` are separated so
    a caller that wants only what is known about this host can take it.

36. **THE CROSS-WORKFLOW LOOP WAS NOT PROVEN, only asserted.** Each
    subsystem had its own suite and every suite passed. Nothing exercised
    hunt -> validated outcome -> verified lesson -> next hunt's decision.
    `eval/test_cross_workflow_integration.py` (43 checks) now does, end to
    end, over a temporary database and a loopback target.

    MEASURED: the first version of that test asserted the wrong thing and
    failed for a reason worth keeping. It called `record_finding` directly
    and asserted the finding had been priority-boosted — but the boost is
    applied by `_recon_http`, the step that DERIVES the class from an
    observed signal and then boosts what it derived. Calling the file
    operation directly bypasses the decision, so the test was measuring
    the wrong function.

    The second version used a second hunt as the control — "a hunt whose
    class has no verified lesson" — and that control was INVALID, because
    `before_recon` deliberately returns verified lessons for every class in
    the corpus. Once `sqli` had a verified lesson, every later hunt that
    raised an `sqli` finding was boosted: a second hunt of the same class
    is not a control, it is a second instance of the treatment.

    The honest A/B is the SAME recon, run BEFORE and AFTER the lesson
    exists. Target, class, signal and code path are identical; the only
    variable is whether the corpus holds a verified lesson. That is the
    comparison the test now makes, and it is the only one that isolates
    the lesson as the cause.

37. **THE EVAL SUITE WAS WRITING TO THE LIVE CANONICAL DATABASE.**
    `eval/test_p0_skill_registry.py` read `con = store.open_db(db)`, where
    `store` is `orch.store`. But `orch.store.open_db` takes NO path — its
    signature is `open_db(create: bool = True)`. The `Path` argument was
    therefore bound to `create`, which is truthy, and the call opened the
    LIVE database (`db/wks.db`) instead of the temporary one. The test
    passed, because the live database has every table the test needs.

    MEASURED on the live corpus: 42 of its 46 `finding` rows were test
    artifacts (`p0.skills.finding.*`, `reach.*.finding.*`,
    `surf.test.finding.*`, `dbg.1.finding.*`, `lab.proof.chain.*`, `f1`,
    `zz.gap`), and all 50 `lesson` rows were test-derived. The damage was
    not cosmetic: the scheduler counts open findings as "potential impact",
    so the system's own health metrics were reading test data as hunting
    output, and a finding's outcome becomes a lesson, which is what the
    hunt layer reads. The pollution also spans several dates (2026-10-04
    onward), so it is a long-standing condition rather than a single run's
    accident.

    The test now redirects `orch.store.db_path` and `wks.config.db_path`
    at its temporary database, and `store.open_db()` is called with NO
    argument so there is nothing to misbind. MEASURED: the live
    `finding` and `lesson_feedback` counts are identical before and after
    a run of the test.

    `tools/quarantine_test_artifacts.py` then quarantined what the leak
    had already written, under I8: every record was EXPORTED to
    `superseded/test-artifacts-<timestamp>/` with a per-record verdict,
    and marked `rejected` in place. **0 rows were deleted** — the live
    database still holds all 46 findings, all 50 lessons, all 44 evidence
    rows and all 310 transitions. What changed is what the system
    presents as live: findings counted as potential impact went 46 -> 0,
    lessons returned as intelligence went 0 -> 0 (every lesson was
    `analyzed`, and `before_recon` reads only `verified`), the 50 gaps
    that named rejected lessons were resolved, and the 40 research
    proposals raised from them were closed.

    The exam harness's own findings (`exam-idor-*`) are deliberately NOT
    quarantined: `wks/assess_evidence.py` creates them by importing a
    GRADED EXAM, and `wks.quality` reads their evidence to decide what may
    be promoted. They are the corpus's evidence base, not a leak.

38. **`WKS_ROOT` CANNOT SANDBOX A SUBPROCESS, and one test relied on it.**
    `eval/test_dispatch_reachability.py` spawns the real CLI as a
    subprocess (`python -m orch.hunt_cli`) and set `WKS_ROOT=<repo>`. The
    intent was to isolate the run; the effect was the opposite.
    `WKS_ROOT` relocates the WHOLE tree, including the code the subprocess
    imports, so a subprocess that must exercise the real code has to keep
    the real `WKS_ROOT` -- and with it, the real `db/wks.db`. The
    subprocess wrote a genuine `finding` row (`reach.*.finding.*`, status
    `validating`) into the live corpus, and the scheduler counted it as
    potential impact. MEASURED: the row appeared at 07:27:30, during the
    suite run.

    The second lever is `WKS_DB`, which relocates ONLY the database and
    leaves the code where it is. `wks.config.db_path()` now resolves:
    `WKS_DB` -> `WKS_ROOT/db/wks.db` -> `<repo>/db/wks.db`. `hunt_cli._con()`
    previously computed `root()/db/wks.db` itself, bypassing `db_path()` and
    therefore bypassing the override; it now goes through `db_path()`.

    The test now creates a temporary database, applies the real schema with
    `orch.store.open_db()`, seeds the FIVE COLLECTION ROLES plus the
    `executor` role, and points the subprocess at it with `WKS_DB`.

    MEASURED, and worth keeping: with an EMPTY database the hunt created
    its recon tasks and then dispatched NOTHING -- the trace file was never
    written, and the check reported "the dispatcher never reached a
    handler", which reads like a dispatch regression and is not one. The
    cause is `orch.agentkit.select_agent`, which ranks the rows of
    `agent_role`: with no roles there is no candidate to select, so
    `agents.dispatch` is never called. The roles are REFERENCE DATA (the
    five collection roles, declared in `orch/collection.py`), not
    operational state, and a database that runs a hunt needs them.

39. **TWO MORE INSTANCES OF THE SAME MISBINDING.** The isolation test
    found what the first fix missed:

    - `eval/test_p0_authorization.py` read
      `store.open_db(path=db) if "path" in store.open_db.__code__.co_varnames
      else store.open_db(db)` -- a workaround for a `path` parameter that
      `orch.store.open_db` DOES NOT HAVE. The `else` branch therefore ran,
      and the `Path` was bound to `create` (truthy), opening the live
      database. It now redirects `db_path` and calls `store.open_db()`.
    - `eval/test_priority_maturity_reconcile.py` opened the live database
      with no redirection at all. It only READS today, so it corrupted
      nothing -- but a test whose RESULT depends on whatever the live corpus
      happens to contain is one `INSERT` away from writing to it.

    THE DISTINCTION THAT MATTERS: `wks.store.open_db(path=None, ...)`
    legitimately takes a path; `orch.store.open_db(create=True)` does not.
    Only the orchestrator's store is the leak vector. The isolation test
    resolves the imported module by AST, so `wks.store` calls are not
    flagged.

    `eval/test_p1_live_db_isolation.py` (20 checks) now enforces all of
    it: the signature check, the AST check, the sandbox check, the
    `WKS_DB` override check, the subprocess check, and a BEHAVIOURAL
    CONTROL -- a real eval file is run and the live database's row counts
    are compared before and after. A source-level check can only find the
    pattern; only the behavioural control finds the effect.

40. **THE GATE GUARD CAUGHT THE `WKS_DB` CHANGE, AND WAS RIGHT TO.**
    `orch/selfaudit.py::_g_gate_integrity` verifies that the six files
    which define the quality gate are byte-identical to their recorded
    fingerprints. Adding `WKS_DB` to `wks/config.py` moved the hash, and
    two suites went red with "the quality gate is unmodified".

    The guard's own message is the correct reading: "thresholds unchanged
    -- review before re-baselining". MEASURED before touching anything:
    `CRITICAL_SETTINGS` verified textually identical on all eight --
    `MIN_PUBLISHER_HOSTS=2`, `MIN_SOURCES=2`, `MIN_CLAIM_CHARS=40`,
    `MIN_BODY_CHARS_SUPPORTED=200`, `MATURITY_MIN_ITEMS=12`,
    `MATURITY_MIN_HIGH_CONF=4`, `MATURITY_MIN_FP_RULES=2`,
    `MATURITY_MIN_CHAINS=1`. `gate_guard.verify()` reported
    `settings_changed: []` and one changed file.

    The database was backed up first
    (`cyber-archives/gate-rebaseline-20261101/wks-pre-rebaseline.db`,
    sha256 `77c3099b60b8fdda036e3ce81d0a6945f0bbbf5f4de9cf7586d427d4850164db`),
    then re-baselined through `gate_guard.baseline(con, reason=...)` --
    which REFUSES without a reason, archives the previous fingerprint, and
    emits an event. The reason names the change, states that no threshold
    moved, and lists all eight values. MEASURED after: 6 files match their
    fingerprints, 0 settings changed, 0 changed files.

    This is the guard working as designed. A hash-only guard would have
    said "tampered"; the threshold check said "the SAFETY did not move",
    which is the distinction that matters.

41. **A READ-ONLY TEST ON THE LIVE CORPUS IS LEGITIMATE; A WRITING ONE IS
    NOT.** `eval/test_priority_maturity_reconcile.py` was sandboxed as
    part of the isolation work, and two of its checks then failed: "the
    live corpus has classes missing a structural capability" and "gap
    weights vary across classes".

    The check names state the requirement: the LIVE CORPUS. Its negative
    control is a class whose item-count bar is cleared but whose
    STRUCTURAL capability (fp_rules / chain / skill / methodology) is
    missing -- a property of the corpus's accumulated state, not of a
    freshly seeded taxonomy. A fresh seed has no such class, so the
    control cannot run and the check reports "only 0 distinct weight(s)",
    which is the check failing to find a condition that is not there.

    The test now opens the live database READ-ONLY (`file:...?mode=ro`), so
    "this test writes nothing" is enforced by SQLite rather than asserted
    in a comment. It reads the corpus because that is what it is for.

42. **THE SUITE NOW LEAVES THE LIVE CORPUS UNCHANGED, AND THAT IS
    MEASURED, NOT ASSUMED.**

    MEASURED after a full `eval/run_all.py` (63 files, 1433s): findings
    `46 rejected + 1 duplicate`, lessons `51 rejected`, live findings
    counted as potential impact **0**, verified lessons returned as
    intelligence **0**, knowledge items **2086**, sources **1100** -- all
    identical to their values before the run. The suite is green AND the
    corpus is untouched.

    The quarantine archives are self-describing and restorable: six
    timestamped snapshots under `superseded/test-artifacts-*`, each with a
    `manifest.json` (findings) and/or `lessons-manifest.json` (lessons)
    naming every archived record, its verdict, its reason and the file it
    lives in. MEASURED: every path named by every manifest exists. Nothing
    was deleted -- the live database still holds all 46 findings, all 51
    lessons, all 45 evidence rows and all 314 transitions.

    The three lesson-only snapshots that predated the manifest were given
    one, reconstructed from their archived record files and marked as
    reconstructed.

### Found by the 2026-11-01 provenance audit

43. **THE QUARANTINE MARKED TEST OUTPUT; THE SYSTEM HAD NO WAY TO KNOW.**
    The previous audit quarantined 44 findings and 51 lessons that the
    test suite had written into the live canonical database. MEASURED on
    the live database after that work: every hunt targeted `127.0.0.1`,
    `demo.example.test` or `app.acme.test` — **there is no production
    data in the corpus at all**, 137 hunts and 47 findings, every one of
    them a test artifact.

    But the SCHEMA had no field that said where a record came from. So
    the quarantine was a one-time cleanup with no structural consequence:
    the next contamination would be counted exactly the same way. And the
    counting was not cosmetic:

      * `orch/scheduler.py::has_useful_work` counted every finding with
        status `candidate`/`validating` as unvalidated impact. Its stop
        condition could not be reached.
      * `orch/hunting.py` computed the hunt's value from the same set, so
        a hunt's value was dominated by contamination.
      * `learning_engine.before_recon` returned every `verified` lesson to
        the next hunt as class-level intelligence.
      * `learning_engine.verify_hook` refused a lesson with NO EVIDENCE,
        but accepted one from any origin. Evidence proves a CLAIM; it
        says nothing about where the claim came from.

    Two columns now carry the eligibility class: `finding.provenance` and
    `lesson.origin`. `lesson.provenance` already existed and is the JSON
    DESCRIPTOR — which hunt, which finding, what evidence — so it is not
    equivalent and was not overloaded. Both default to `UNKNOWN`, the
    fail-closed direction. `orch/provenance.py` owns the vocabulary and
    the rules; the columns are only the storage.

    Enforced at every point that matters: `add_finding` derives the
    origin from the context it was given; `orch/hunt_exec.py` sets it from
    the hunt's target and authorization kind; the learning bridge
    INHERITS the finding's origin; `verify_hook` refuses an ineligible
    lesson; `before_recon`, `before_summary` and `_prior_for_signal` read
    only eligible lessons; and the scheduler's and the hunt's impact
    counts are provenance-filtered. `eval/test_p2_provenance.py` (13
    tests) pins the property: a test finding cannot become hunting
    experience.

    The live corpus was classified by `tools/apply_provenance.py`, which
    reads the audited disposition manifest and writes the origin — two
    tools, so the decision stays auditable against an artifact. MEASURED
    after applying: 45 findings `EVAL_TEST`, 2 `EXAM_FIXTURE`, 51 lessons
    `EVAL_TEST`; **0 records eligible for impact**, 0 verified lessons
    returned as intelligence. The classification is idempotent — a second
    run reports 0 changed, 98 unchanged. The pre-apply database is
    retained at `db/wks-pre-provenance-apply-20261101T141325Z.db`.

44. **THE FIX HAD A SECOND-ORDER EFFECT: REAL WORK WAS ALSO EXCLUDED.**
    The first implementation made `add_finding` default to `UNKNOWN`,
    which is fail-closed — and fail-closed in BOTH directions. A real
    hunt finding filed by `orch/hunt_exec.py` was also ineligible, so the
    impact calculation would have read zero on a corpus of genuine
    findings. The quarantine made test output visible; nothing made real
    output eligible.

    So an unspecified provenance is now DERIVED from the context the
    caller already supplied: the `validator_run` that names the exam
    harness, and the target, which cannot be a production target if it is
    the loopback address or a reserved test domain. A hunt against a real
    target is a `PRODUCTION_HUNT`; a hunt against `127.0.0.1` or
    `example.test` is an `EVAL_TEST`. The write-up path declares
    `IMPORTED_RESEARCH` — a published write-up is not a hunt, so it is not
    impact, but it IS eligible to become experience.

45. **FOUR SQL FRAGMENTS READ THE WRONG COLUMN.** `orch/provenance.py`'s
    `trusted_lesson_clause` and `promotable_clause` compared
    `lesson.provenance` — the JSON descriptor blob — against the
    vocabulary. That never matches, so the clauses silently selected
    NOTHING: `trusted_lessons()` and `promotable_lessons()` returned
    empty for every lesson in the corpus. `provenance_of` and
    `set_provenance` had the same bug, and `set_provenance` on a lesson
    would have OVERWRITTEN the descriptor with a vocabulary word,
    destroying the record of where the observation came from.
    `provenance_report` initialised `"findings"`/`"lessons"` and filled
    `"finding"`/`"lesson"`, so the two keys it promised were always empty
    and every caller reading them raised `KeyError`. All four are fixed,
    and `eval/test_p2_provenance.py` pins the clause behaviour.

46. **THE SCHEMA INDEXED A COLUMN THAT DID NOT EXIST YET.**
    `orch/schema.sql` created `ix_finding_provenance ON
    finding(provenance)` unconditionally. `CREATE TABLE IF NOT EXISTS`
    does not add a column to a table that already exists, so on the live
    database — whose `finding` table predated the column — the index
    statement failed with "no such column: provenance" and took the whole
    schema script with it, so the database could not be opened at all.
    The index belongs to the MIGRATION that adds the column
    (`orch/store._migrate_provenance`), because only that code knows
    whether the column is present. `learning_engine.ensure_schema` has
    the same problem for `lesson.origin` and migrates it the same way.

## Known limitations

MEASURED 2026-10-31: the first bullet below and the "15 classes seeded" bullet
were written when the corpus held 15 classes. The second is now false — every
class named in it is registered and holds items — and has been replaced with
the limit that is actually true today.

- Retrieval is lexical. A paraphrase with no shared vocabulary will not match;
  there is no semantic fallback. Mitigated by OR-terms + BM25, not solved.
- ~~15 classes seeded. Absent: SSRF-chain cloud variants, HTTP request
  smuggling, cache poisoning, prototype pollution, WebSocket, HTTP/2-specific,
  prototype pollution, XXE, subdomain takeover, supply chain.~~ **Superseded** —
  all of those classes are now registered and hold items; the corpus is 70
  classes with 44 `mature`, 26 `researching`, 0 `planned`. The live limitation
  is different and sharper: **the FP-rule gap blocks 24 classes**, and
  `fp_case` rows must come from real hunting outcomes rather than being
  written to clear the gate (see "Next work" item 3).
- The gate measures evidence structure, not technical truth. Two credible sources
  can still be wrong; `conflict` records exist for that but nothing populates
  them automatically yet. **Measured**: 192 conflicts raised, 30 resolved,
  154 dismissed, 8 open — so the mechanism does run, and 8 are still live.
- No automatic staleness re-review: `outdated` is a state the system can hold but
  does not yet apply on its own.
- **A citation can be live and still prove nothing.** R28 now has standing
  checkers for this (`tools/audit_rfc_subjects.py`, `tools/audit_seed_subjects.py`),
  but they judge the SOURCE's subject. A page can be on-topic and still not
  support the specific sentence it is cited for; that is a reviewer judgement,
  not a mechanical check, and the corpus has no automatic guard for it.
- **A lock holder that dies without releasing is now reclaimed, but the
  reclamation is local.** `wks/migration_lock.py` detects an abandoned lock
  by testing whether the recorded pid is still running (defect 14). That
  test is only meaningful while the pid namespace is shared between the
  writer and the observer: a lock row written by a process in another
  namespace (a container, a different WSL distro, a remote mount) has a pid
  that is either unknown or meaningless here, so it is waited out rather
  than stolen — deliberately, since stealing a live lock is worse than
  waiting. The consequence is that a genuinely abandoned cross-namespace
  lock still blocks writers until its timeout. This is a known limit of a
  pid-based liveness check, not a hidden failure.
- **231 citations are paraphrases stored as quotes, and the corpus has no
  automatic guard against it.** MEASURED 2026-10-31 (defect 17): 69% of the
  citations that fail a verbatim match carry the source's meaning with
  reworded phrasing, and a further 21% are loose paraphrases. The gate
  proves a quote is real and cited by independent publishers; it cannot
  prove the stored wording is the source's wording, because the stored
  wording is often not the source's. `tools/quote_fidelity.py` measures
  the gap, but nothing yet PREVENTS a paraphrase from being written, and
  repairing the existing 231 is a per-citation research task rather than a
  bulk operation — a bulk rewrite that invents replacement quotes would
  manufacture the very defect it is meant to fix. This is the live
  limitation; it is named, measured and owned, not hidden.
- **Quote verification is a network operation and the corpus is large.**
  3,418 citations over 922 URLs is ~4 minutes at 12 workers, and it is
  throttled by the hosts it reads: MEASURED, two concurrent corpus-wide
  audits drove each other's fetch success from 98.6% to 25%, because the
  same hosts were hit twice. The audit tools take `--workers` for this
  reason and must not be run concurrently against the same corpus.

## Next work, in priority order

MEASURED 2026-10-31: this list was written when the corpus was 15 classes and
157 active items. It is re-measured against the live corpus below; the
"Known limitations" section above carries the same staleness and is corrected
separately.

1. ~~Ingest the delegated research for idor / oauth / race / graphql~~ —
   **done**: all four hold 12–14 gated items, and the 21 open
   `fabricated-evidence` conflicts they produced have been settled (0 open).
2. Add 8–10 chained relationships between those classes (§10). **done** —
   79 chains and 70 classes now exist, and every registered class has at
   least one chain step.
3. Write the FP-rule capture path from real hunting outcomes (§17).
   **partly done**: `fp_case` rows went 6 → 88, but `fp_rules` is now the
   gap blocking **24** classes from reaching `mature` — `ad_enumeration`,
   `ad_ldap`, `ad_ntlm`, `ad_trust_abuse`, `adcs_abuse`, `api_trust`,
   `container_escape`, `credential_access`, `crlf`, `deser`, `dns_enum`,
   `eol_software`, `internal_recon`, `linux_privesc`, `otp`,
   `pass_the_hash`, `prototype_pollution`, `rate_limit`,
   `segmentation_analysis`, `service_enumeration`,
   `service_enumeration_detail`, `tunneling_pivoting`,
   `windows_privesc_token`, `xxe`. This is now the single largest
   maturity blocker, and `python -m wks.cli gaps` ranks them.
4. ~~Close the remaining 7 `planned` classes: `authz`, `bizlogic`, `csrf`,
   `deser`, `mass_assign`, `path_traversal`, `ssti`~~ — **done**: 6 of the 7
   are now `mature` (`authz`, `bizlogic`, `csrf`, `mass_assign`,
   `path_traversal`, `ssti`); only `deser` remains `researching`, blocked on
   `fp_rules`. No class is `planned`.
5. Automatic conflict detection between same-class high-confidence items.
   **partly done**: 192 conflicts raised, 30 resolved, 154 dismissed, 8 open.
   The 8 open conflicts are the remaining work.
6. ~~Resolve the 4 `DUPLICATED` methodology classes reported by
   `check_methodology_coverage.py`~~ — **done**: the check now reports 70/70
   covered and no class has a missing methodology path.
