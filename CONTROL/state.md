# Live state (mutable)

This is the only file in `CONTROL/` that changes during a run. The constitution
does not change because a hunt had a bad day.

## Current phase

**Phase 14 — orchestration.** The knowledge engine (Phase 13) is unchanged and
still green. A new `orch/` layer now sits on top of it in the same database,
owning WORK rather than knowledge.

| Component | Path | State |
|---|---|---|
| Task DAG | `orch/dag.py` | edges-derived readiness, cycle detection+repair, parallel waves |
| Priority engine | `orch/priority.py` | 7 declared weights, explainable, self-reordering |
| Validation | `orch/validate.py` | L1–L6; L4 refuses a self-validating claim |
| Agents | `orch/agents.py` | roles as data, recursion budget, claim/validate separation |
| Orchestrator | `orch/orchestrator.py` | decompose → rank → dispatch → gate → checkpoint |
| Events | `orch/events.py` | 4-factor relevance; lead-only ceiling in the scorer |
| Workers | `orch/workers.py` | 5 named workers, heartbeats, crash recorded not swallowed |
| Scheduler | `orch/scheduler.py` | multi-cycle supervision with a real stop condition |
| A/B | `orch/abtest.py` | refuses verdicts the evidence does not support |
| Self-audit | `orch/selfaudit.py` | 18 checks; health = weakest dimension, not an average |
| CLI | `orch/cli.py` | 15 subcommands |

**Verified:** 288 orchestration checks pass across 11 suites, the WKS gate
regression is intact, and the quality gate is fingerprinted (self-audit 20/20).

| Suite | Checks | Covers |
|---|---|---|
| SPINE | 58 | store/dag/scope/validation |
| ORCHESTRATOR | 47 | end-to-end execution |
| ISOLATION | 9 | wks/orch write separation (measured) |
| SCHEDULER | 21 | cycles + stop condition |
| ABTEST | 20 | refusal paths |
| CRASH | 15 | real os._exit(9) recovery |
| AUTHORIZATION | 19 | capability + scope gates |
| REGRESSION | 27 | defects found by an independent agent |
| EXECUTOR | 32 | the real executor's honesty rules |
| GATE_GUARD | 17 | gate tampering detection (6 files now) |

The system now runs unattended: cron job `cyber-orchestrator-overnight`
(every 3h) drives gate check -> audit -> `run --execute` -> supervise ->
stopcheck, and refuses to proceed if the gate fingerprint has moved.

`orch/` and `wks/` are two owners of one database file, and that separation is
MEASURED, not asserted: `eval/test_isolation.py` traces every write during a
full orchestration workload and asserts the write set contains no knowledge
table. The orchestration write set is
`agent_role, agent_run, checkpoint, event, task, task_dep, worker_heartbeat`.

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

## Architecture as built

| Component | Path | State |
|---|---|---|
| Canonical store | `db/wks.db` (SQLite, FTS5) | working |
| Schema | `wks/schema.sql` | 12 tables + FTS + 3 triggers |
| Quality gate | `wks/quality.py` | 10-dimension vector, 4 hard gates |
| Retrieval | `wks/retrieval.py` | BM25 + trust-prior blending |
| Pipeline | `wks/pipeline.py` | ingest, sanitize, seed verify, markdown |
| Taxonomy spec | `tools/taxonomy/taxonomy_spec.py` | 51 class pages, 15 stubs, 7 chains, 6 sub-docs |
| Coverage | `tools/taxonomy/check_methodology_coverage.py` | reads `bug_class.methodology`; 15/15 covered |
| Metrics | `wks/evalm.py` | 13 metrics + 8 retrieval probes (7 tested, 7 pass, 1 `no_knowledge`) |
| Cycle | `wks/cycle.py` | 12-step autonomous loop |
| Tests | `eval/test_wks.py` | 17 tests / 63 assertions, all pass |

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
  current gate. See `state/legacy-audit.json`.

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

## Known limitations

- Retrieval is lexical. A paraphrase with no shared vocabulary will not match;
  there is no semantic fallback. Mitigated by OR-terms + BM25, not solved.
- 15 classes seeded. Absent: SSRF-chain cloud variants, HTTP request smuggling,
  cache poisoning, prototype pollution, WebSocket, HTTP/2-specific, prototype
  pollution, XXE, subdomain takeover, supply chain. These are *planned* gaps,
  tracked in the `bug_class` table as they are added.
- The gate measures evidence structure, not technical truth. Two credible sources
  can still be wrong; `conflict` records exist for that but nothing populates
  them automatically yet.
- No automatic staleness re-review: `outdated` is a state the system can hold but
  does not yet apply on its own.

## Next work, in priority order

1. ~~Ingest the delegated research for idor / oauth / race / graphql~~ —
   **done**: all four hold 12–14 gated items, and the 21 open
   `fabricated-evidence` conflicts they produced have been settled (0 open).
2. Add 8–10 chained relationships between those classes (§10).
3. Write the FP-rule capture path from real hunting outcomes (§17) — only 6
   `fp_case` rows exist and `fp_rules` is the gap blocking 5 of 8 researched
   classes from reaching `mature`.
4. Close the remaining 7 `planned` classes: `authz`, `bizlogic`, `csrf`,
   `deser`, `mass_assign`, `path_traversal`, `ssti`. `wks.cli gaps` ranks them.
5. Automatic conflict detection between same-class high-confidence items.
6. Resolve the 4 `DUPLICATED` methodology classes reported by
   `check_methodology_coverage.py` (csrf, idor, ssrf, xss each have both a
   hand-authored page and a generated view).
