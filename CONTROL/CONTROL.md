# CONTROL — constitution (invariant)

This file states what does not change. Mutable state lives in `state.md`.
Enforceable rules live in `rules.md`, each with how it is checked.

Superseded control surfaces are preserved verbatim under `superseded/`.

## Mission

Build and continuously improve a **dual-domain** offensive security knowledge
system — WEB and NETWORK — that is evidence-backed, retrievable,
validation-aware, and honest about its own gaps. Knowledge that cannot change a
hunter's next request does not belong here.

The two domains are organisational siblings, not a hierarchy:

```
CYBER
├── WEB            browser- and API-mediated HTTP surfaces
├── NETWORK        internal network, infrastructure, and on-premises AD
│                  ├── INTERNAL_NETWORK
│                  ├── INFRASTRUCTURE
│                  └── ACTIVE_DIRECTORY
└── SHARED CORE    learning · methodology · validation · evidence · reporting
```

**The shared core is shared.** There is one gate, one corpus, one evidence
model and one reporting path. A second validation mechanism inside NETWORK would
be the architecture's central defect, not a specialisation of it.

**Active Directory is not a third domain.** It is a specialization under
NETWORK, because every AD attack path is reached by network access to a
protocol — a ticket cannot be forged without reaching a KDC. Promoting AD to a
domain would give one body of knowledge two canonical homes and force the router
to guess which one an objective meant.

## Invariants

**I1 — A citation is not proof.**
No item reaches `supported` or `high_confidence` without evidence from at least
`MIN_PUBLISHER_HOSTS` distinct publisher hosts. Two pages on one host is one
publisher. Enforced in `wks/quality.py::assess`, locked by `eval/test_wks.py`
T2.

**I2 — Evidence must be inspectable.**
Every promoted item carries the URLs it rests on and, where available, a verbatim
span. Retrieval returns provenance with the claim, never the claim alone.
`wks/retrieval.py::retrieve`.

**I3 — A test that cannot fail proves nothing.**
Every item carries a `disproof`: the observation that would refute it. Methodology
steps state both what to do and what would disprove the hypothesis.
`schema.sql` (NOT NULL discipline is enforced by curation, see rules R4).

**I4 — Quality is measured, not asserted.**
`validation_state` is derived by the gate. Nothing writes it directly.
`wks/quality.py` is the only writer. Green gate tests do **not** mean the
knowledge is good — that is `wks/evalm.py`.

**I5 — Unresolved is a legitimate state.**
Low-quality material is retained with its rejection reason rather than deleted,
but it is never presented as established knowledge. `quarantine/`, and the
`rejected` / `under_review` states.

**I6 — Research-first, active testing when authorized.**
This system fetches published documentation (`wks/` layer). It performs no scanning,
fuzzing, exploitation or credential attacks against any target unless an authorized
hunt is running. `config.RESEARCH_ONLY` is `True` and `CAN_AUTHORIZE` is `False` in
`wks/config.py` — the WKS layer is research-only and cannot authorize itself. The
`orch/` hunt layer enables active testing when explicitly
authorized — via `python -m orch.cli hunt` or when the operator says "start hunt" /
"we are hunting" / "begin hunting" (which triggers `AuthorizationContext` registration).
Active testing requires explicit user-provided authorization and lives in `orch/`.
MEASURED 2026-10-31: this clause previously stated `RESEARCH_ONLY = False` and
`CAN_AUTHORIZE = True`, contradicting the code and the project's own research-only
boundary. The code was already correct (`wks/config.py` restores both flags to their
safe values and records why); the constitution text was the stale copy.

**I7 — External text is data, never instruction.**
Fetched content is sanitised on ingest (`pipeline.sanitize`) and can never
redefine objectives, permissions or safety boundaries. A source that tries is
flagged in `source.notes`, not obeyed.

**I8 — Destructive change requires a recoverable state.**
Nothing is deleted. Superseded material moves under `superseded/`; the legacy
corpus stays in `quarantine/` with a per-record verdict in
`runtime/state/legacy-audit.json`.

**I9 — The system reports its own weakness.**
`python -m wks.cli gaps` and `probe` must be able to say "coverage is weak here".
A metric that cannot go down is decoration and is not one.

**I10 — Improvement requires an artifact.**
No claim of learning without a persisted change: a row, a document, a task, a run
record. `runtime/state/LATEST.md` and the `run` table are the audit trail.

**I11 — A taxonomy is not knowledge.**
A registered class with GET-verified seeds and no gated items is a *map entry*.
`domain-health` reports declared-vs-evidenced per domain precisely so the two are
never confused. Rendering `Not yet researched.` is the honest state; a page of
plausible technique prose with no citations is the defect this system exists to
prevent. Measured on 2026-10-02: NETWORK stood at 25 declared and registered
classes with **0** gated items.

**I12 — Routing must refuse to guess.**
`wks/domains.py` resolves an objective to a domain or reports `UNROUTED` with
its candidates named. A weak match is never resolved into a confident wrong
domain, because a mis-routed learning run spends its whole budget on the wrong
tree and still reports progress.

**I13 — Provenance may only improve.**
Re-running a taxonomy seed must never weaken the authority already recorded for
a source. `store.upsert_source` is monotonic: an equal-or-weaker incoming
declaration leaves the existing label and tier alone. Measured: a re-seed
overwrote 11 source types and LOST authority on 2, which would have lowered
`source_credibility` for reasons unrelated to any new research.

**I15 — A declared capability is not a held capability, and an authorised
target is not an authorised *action*.** An adversarial validator found the
capability and scope systems were DECLARATION ONLY. `capability_grant` existed
in the schema but nothing could ever write it, so a gate requiring a grant was
permanently closed rather than meaningfully enforced. `check_scope` was never
called from `dispatch`, the orchestrator, or any worker — a role declared
`["READ" … "DESTRUCTIVE"]` at depth 5 dispatched with **zero** authorization
records in the database. `apply_validation` trusted the caller's verdict
string, so `apply_validation({"verdict": "validated"})` marked a finding
validated that had passed nothing.

Three rules follow, enforced in `agents.dispatch` (not in the caller — a gate
only a well-behaved caller remembers is not a gate):

1. **Declare AND grant.** `agents.authorize_target` requires the level in the
   role's capability list *and* a matching `capability_grant` row.
2. **Authorised ≠ offensive-permitted.** An EXECUTE/DESTRUCTIVE role needs
   `offensive_allowed`, not merely a matching scope row. A `research_only`
   grant permits recognising a target, never exploiting it.
3. **Verdicts are re-derived, never trusted.** `apply_validation` recomputes
   the L1–L6 vector and uses *that* verdict; the caller's string is ignored.

READ/ANALYZE/WRITE are deliberately ungated — they act only on this system's
own state, and gating them would make the orchestrator unusable without a grant
just to read its own database. `eval/test_authorization.py` (20 checks) proves
each gate can fail; the validator's original exploit now returns
`dispatched: False` with the denial reason attached.

**I16 — A blocked state that can never be left is a graveyard, not a safety
mechanism.** An adversarial validator (separate agent, 14 defects reproduced by
execution while all 105 of my own checks were green) found `refresh_readiness`
only ever moved tasks INTO `blocked`. Once a dependency failed, its dependents
stayed `blocked` forever — even after the dependency was repaired and completed
— so a single transient failure poisoned a chain for the life of the database.
`blocked` and `retrying` are now re-evaluated on every pass, and revived only
when every dependency has reached a success state. Never re-admit on "merely
still running": that would let a task be claimed out of order.

**I17 — Authorization must name ONE concrete target.** `check_scope` used
`LIKE '%' || ? || '%'`, so `check_scope("")` matched every grant, `check_scope("%")`
matched every grant as a wildcard, and `check_scope("lab.intern")` matched the
granted `lab.internal`. All three returned `authorized=True`. The gate now
matches the host EXACTLY (case/space normalised), refuses empty and wildcard
targets outright, and compares `expires_at` as a DATE — a malformed value like
`"not-a-date"` is treated as EXPIRED, because failing open on corrupt data turns
a lapsed authorization into a permanent one.

**I18 — Absence of a party is not independence; absence of evidence is not a
pass.** `check_independence` compared run-key strings and treated a missing
validator as "unknown", so `validate_finding(con, key, reproduced=True)` — with
no claimant anywhere — passed L4 and reached `verdict='validated'` at 6/6 with
no independent agent in the system. L4 now requires BOTH a claimant and a
validator, and additionally requires them to hold **different roles**: one agent
producing and validating a claim is one agent however many run keys it used.

**I19 — A green audit must not be able to mean "stuck".** The stall check
returned `True` unconditionally, so a graph with zero ready work and everything
blocked audited as `healthy 18/18` — the exact situation a self-audit exists to
catch. There is now a `the run can make progress` check: pending work with
nothing runnable and something dead-ended reports `degraded`. The stall check
itself now CONSTRUCTS a stalled sub-graph and asserts it is representable.

`eval/test_regressions.py` (27 checks) covers I16–I19. All of these were found
by an agent that was not the author, with my own suite green throughout — which
is the standing argument for independent validation over self-assessment.

**I20 — The executor must refuse before it fabricates.** The orchestrator could
decompose, rank, dispatch, gate and audit, but for the whole first build no
component actually PERFORMED a task: `completed tasks: []`, and a run reported
"executed 12 task(s)" for work no executor ever did. Removing the stub was
correct but left the OS unable to act.

`orch/executor.py` is the real executor. It performs research ingest (through
the existing gate, with live quote verification) and maintenance (re-gate,
rebuild projections and the FTS index, regenerate docs and skills, recover
orphans). It is bound with `executor.bind(con)` and enabled with
`--execute`, never by default.

Its honesty rules, each of which was violated first and then fixed:
  * **A task completes only with a real artifact.** `ok=True` and no summary is
    `retrying`, not `completed`.
  * **Work already done closes as `superseded`**, not `completed` — "I did this"
    and "this was already done, here is the proof" stay distinguishable forever.
  * **Knowledge the gate rejected is reported as rejected**, never forced in.
    9 pending entries across graphql/race/idor/ssrf/xss were refused because
    their quotes did not verify; that is the anti-fabrication design working,
    so those tasks close with an artifact saying exactly that.
  * **A class is satisfied only by its own entries.** `startswith` let
    `ad_kerberos` match every `ad_*` class; membership is now `cls.` or exactly
    `cls`.
  * **A refusal names the handler** and what was missing.

Result of the first live run: backlog drained from 40 ready to **0**, with 22
`completed` and 15 `superseded`, no knowledge lost. `eval/test_executor.py`
(30 checks) covers it.

**A stale wave listing is not a failure.** `pending` is computed once at the top
of a wave, so a task can reach a terminal state before the loop reaches it —
another task in the same wave, or a concurrent run, may have finished it. The
resulting refused claim was reported as `failed`, which is a false negative
reproduced live: `seed.path_traversal.research` printed FAIL while its actual
state was `superseded` with a valid artifact. A refused claim now re-reads the
task and reports `already_done` when it is terminal, and the CLI's exit status
counts only genuine failures. `eval/test_executor.py` E12 reproduces the race.

**I21 — The gate must be fingerprinted, and a guard must not execute what it
guards.** During the build, `config.py` and `quality.py` were modified by a
process outside the session that owned them. The edit happened to STRENGTHEN
the gate (builder pages excluded from the publisher count), so nothing failed —
it succeeded by luck, not design. Had it set `MIN_PUBLISHER_HOSTS = 1`, two
pages from one author would have satisfied the host rule and the audit would
still have read healthy.

`orch/gate_guard.py` fingerprints the five gate files and reads the eight
critical thresholds **textually, never by import** — a guard that executes the
file it protects cannot protect it. `python -m orch.cli gate` verifies;
`--baseline` is REFUSED without `--reason`, archives the previous fingerprint,
and emits an event, because a guard that can be re-baselined silently is not a
guard. A modified gate file is a self-audit FAILURE (check 20 of 20), and a
threshold change is reported by name with both values
(`MIN_PUBLISHER_HOSTS 2 -> 1`). A comment-only edit is reported as modified
but as no safety change — the distinction is the point.

`eval/test_gate_guard.py` (17 checks) proves each path can fail, including a
weakened threshold, a deleted gate file, and an audit that goes `degraded`.

**The guard's first real catch was this agent's own author.** Adding
`class_domain` to `schema.sql` made the fingerprint mismatch, and `orch gate`
returned non-zero until it was re-baselined with a reason. That is the guard
working: it caught a deliberate, justified change by the person who wrote it.

**I22 — A table that exists only in one db file is not part of the schema.**
`class_domain` was in the live database but absent from `schema.sql`, so every
freshly-created database — a dry run, a test scratch db, a new install — raised
`no such table: class_domain` the moment `skillgen` rendered a skill. That
crash took the ENTIRE knowledge-gate self-test down with it, and a gate that
dies on a data gap reports nothing, which is indistinguishable from a gate that
passed. Two fixes, both structural: the table is in `schema.sql`, and
`domains.class_dir` returns an `_unmapped/` path instead of raising on a class
with no domain. `wks/domains.py` was then added to the fingerprinted set —
anything whose failure takes the gate down belongs under the guard, not just
the gate itself.

**I23 — Independence is per registrable domain, and BOTH errors are failures.**
The 2-publisher rule is what stops one author from corroborating themselves by
writing two pages. Counting hosts is not enough: `wstg.owasp.org` and
`cheatsheetseries.owasp.org` are two hosts and one editorial voice. But an
independence check that over-collapses is ALSO broken, and it fails quietly: it
discards real corroboration and looks like strictness. `orch/researcher.py`
therefore reduces to eTLD+1 and applies one explicit extra rule (all of
`owasp.org` is one voice), rather than pattern-matching a suffix list.

**I24 — Evidence keys are a contract, and the gate reads a specific one.**
Autogenerated items were rejected with "insufficient publisher hosts" while
every quote verified. The gate counts distinct `host` values; the producer
emitted `publisher`. Nothing was wrong with the knowledge and nothing said the
key was unknown. A contract mismatch must fail loudly at the producer.

**I25 — The stop condition is the state a cycle STARTS from.** `run_cycle`
evaluated `has_useful_work` AFTER running its workers, but `auditor` and
`triage` open an event as part of doing their job — so the cycle always saw the
event it had just created, `open_events` ratcheted up by one per cycle, and the
supervisor burned its whole budget on an empty system. It is now read before
the workers run, with `stop_condition_after` retained for observability.

**I26 — Extraction bugs hide because the evidence is still "real".** Two
measured: a sentence splitter that cut at the period in "e.g." produced
fragments which passed `verify_span` (they ARE substrings) and were then
rejected by the gate as unverifiable; and a topical filter using `len(w) > 3`
silently dropped `xss` and `csrf` — the shortest class names, and the two most
worth researching. Neither raised an error. Both produced an empty result that
looked like "no evidence available".

**I27 — A span may only be cited against the page it came from.** Spans were
pooled by registrable domain, so two snyk.io pages merged into one pool and each
span was attributed to whichever of that publisher's URLs sorted first. A span
lifted from `/find-and-fix-xml-entity-vulnerabilities` was cited against
`/nokogiri-xxe-vulnerabilities`, which does not contain it. The gate rejected
13 of 16 such items as `QUOTE_NOT_FOUND_ON_CITED_PAGE` and was right — that is
the exact fabrication the corpus exists to refuse. Pooling must be keyed by
`(domain, url)` and every entry carries its own URL.

**I28 — Yield limits must be measured, not assumed.** Three separate caps were
each costing real evidence: publishers chosen alphabetically (so `bishopfox`
with 3 spans beat `httpwg` with 52, purely because "b" sorts first), a pairing
bounded by `min()` of the top two publishers, and an iteration cap of `max()`
where the sum was correct. Fixing all three took the corpus from 43 to 62
mature classes. A cap that is never exercised against a real page is a guess.

**I29 — A "created" report is a claim, so verify the row landed.** `ingest_claim`
silently dedupes on `item_key`. An off-by-one in the derived-fp_rule key search
(the first rule uses an UNSUFFIXED key, so testing only `derived{n}` never saw
it) returned the same key, and the function reported `created` while the class
stayed at one fp_rule forever. Read back the count, not the return value.

**I30 — A test premise can expire without the test being wrong.** `S2` asserted
`weakest_class is not None` as a work source. When the corpus reached 62/62
mature, no weak class exists — correctly — and the assertion started failing.
The fix was to assert the CONTROL property (the loop stays alive while ANY work
source exists) rather than to manufacture a weak class to satisfy it.

## Layer ownership

```
CONTROL/    constitution (this file), rules, live state, operator grammar
wks/        the knowledge engine: schema, gate, retrieval, pipeline, cycle,
            metrics, domains (routing), network_taxonomy (the second domain's
            class map)
orch/       the ORCHESTRATION layer: store, dag (task graph), priority,
            validate (L1-L6), agents (roles/recursion), orchestrator (the
            loop), events (relevance), workers (background), selfaudit,
            cli. Owns WORK, never knowledge.
bug-classes/  CANONICAL vulnerability map — one home per class
  web/      browser-and-server HTTP surfaces
  api/      the same boundaries through an API surface
  network/  the second domain
    internal-network/ · infrastructure/ · active-directory/
attack-chains/ relationships BETWEEN classes, one file per chain family
methodology/   how to approach — entry points + generated class views
skills/     GENERATED per-class skills, versioned
validation/ the gates, the evidence a report needs, FP discipline
reporting/  report structure and severity
learning/   the learning loop workspace: goals · tasks · evidence · gaps
research/   fetched source material + agent intake (incoming/)
classes/    GENERATED per-class evidence digest (from db/wks.db)
chains/     GENERATED per-chain evidence digest (from db/wks.db)
eval/       gate regressions, domain-router regressions, lab forge, legacy audit
state/      run records, audits, seed verification, domain seed probes
tools/      one-shot acquisition helpers used by research briefs
db/wks.db   canonical structured store — the single source of truth
```

**Ownership rule (§13):** the database is canonical; `bug-classes/`,
`classes/`, `chains/`, `methodology/derived/` and `skills/` are projections
generated from it and may be deleted and rebuilt at any time. `CONTROL/` is
hand-authored and is NOT a projection. Never hand-edit a generated file; edit
the row or the spec and re-run the generator.

**`wks/` and `orch/` are two owners of one database file.** `wks/` writes
knowledge; `orch/` writes work. The split exists so either can be removed
without taking the other down, and so a change to research plumbing cannot
break task scheduling. Neither writes the other's tables. Measured 2026-10-02:
`orch/` writes `task` status and `fp_case`, and never touches `item`,
`quality.validation_state`, or `item_source`.

**No stub executor may complete a task.** A run that reports success without
producing an artifact is a *failure*, and the artifact gate
(`orch/validate.validate_task_artifact`) enforces it. This is recorded because
it was violated during the build: a default `{"ok": True}` executor marked 12
research tasks `completed` while producing no knowledge, and the overnight
report read "executed 12 task(s)" — a report that looks like progress. Those
rows were reverted and the default executor removed; `orch run --demo` now
refuses to run without `--sandbox`, and the sandbox proof is a measured
before/after row count, not a promise.

**I14 — A crashed process is indistinguishable from a slow one until time
passes.** An adversarial validator found that a hard-killed run
(`os._exit`, SIGKILL, power loss) left `task.status='running'` AND
`agent_run.status='running'`; because liveness was judged from the agent_run
row alone, `orphan_recovery` saw a "live" agent and recovered **nothing** —
the task stayed `running` across a restart, permanently. This is the exact
stall recovery exists to prevent, and it was invisible because every check
looked like it passed.

Liveness is therefore time-bounded, not row-bounded: a run counts as live only
if it is non-terminal AND its `started_at` is recent (`stale_after_s`, default
900s). A run older than that is a corpse and is closed as `timeout`.
`eval/test_crash_recovery.py` reproduces the kill with a real `os._exit(9)`
subprocess — an exception cannot stand in, because it unwinds and runs
`finally` blocks, which is precisely the cleanup a power loss does not perform.

**An unproven crashed task goes to `failed`, never back to `ready`.** Recovery
makes work *decidable* again; it does not guess whether the interrupted work
finished. Re-running work of unknown completion duplicates it. A task WITH a
recorded result goes back to `ready`, because there the artifact proves the
work happened.

There is deliberately **no top-level `knowledge/` layer**. It was declared here
for months while staying empty, and `db/wks.db` plus `learning/knowledge/` is
where gated findings actually live. An architecture document that lists a layer
which does not exist is worse than one that omits it.

**I31 — A hunt needs its own runtime, and a score needs a falsifier.**
The orchestration layer knew how to schedule work and gate findings, and had NO
hunt layer: no authorization context, no attack surface, no hypothesis engine, no
specialists, no finding lifecycle, no final report gate, no hunt dossier. Sections
1-62 of the master prompt described a system; `orch/` implemented roughly a third
of it and the difference was invisible because nothing measured it.

`eval/masterprompt_score.py` maps all 62 sections to 65 executable checks. Three
properties make the number mean something:

* **Every check is EXEC, DATA or WIRE**, and a WIRE check proves the control
  holds from a path a well-behaved caller could bypass. The 12 controls this build
  added were all WIRE for that reason.
* **`--selftest` proves the harness can fail.** It breaks 10 enforcement points
  and asserts each check goes red. It found its own first version asserting the
  INVERSE polarity — a harness that passes while its control is broken is worse
  than none, because it looks like evidence.
* **The harness never writes to the live corpus.** `run_one` sweeps probe rows
  after every check, including one that raised. Cleanup alone leaked four
  `task_dep` edges whose `task` rows were deleted: a dangling edge outlives its
  row, its dependent silently never becomes ready, and the live self-audit went
  red.

A defect class this build found and did not expect: **a check that fails is not
necessarily a system failure.** Roughly a third of the first run were harness bugs
(a `cleanup()` that could not take SQL bindings, state read after `con.close()`,
a subprocess inheriting another check sandbox `WKS_ROOT`). Each was reported as a
system defect until fixed. Blame has to be assigned before it is fixed, or the
score gets spent repairing code that was never wrong.

**I32 — A refusal with no ledger is a control nobody can audit.** Four defects of
the same shape: the authorization gate read a table nothing created; the final
gate read the tool ledger and the scope ledger without ensuring either existed;
`apply_gate` read a `passed_count` key `gate` never returned, so CLEARING the
gate raised on the way to writing the report. In every case the most valuable
action in the module was the one action that could not complete, and nothing
reported it. An inspection function that raises on missing data is reporting a
crash where the truth may be an absence of evidence.

**I33 — A green suite proves the suite ran, not that the path is wired.** The
2026-10-31 audit found the single worst defect of the project hiding behind a
suite that reported green in full: `ActiveHuntExecutor.can_handle` returned
False for every key, so no hunt task ever reached a handler. The hunt still ran,
still exited 0, still printed a clean summary, and still gated fourteen
candidate findings — every one of them produced by the maintenance path rather
than by any probe. The cause was structural, not careless: every other suite
called a component directly and asserted its return value, so the WIRING between
the dispatcher and the handler was invisible to all of them by construction.

Two consequences generalize past this defect. First, **a capability test that
answers "no" must fail loudly somewhere.** `can_handle` returning False was
indistinguishable from a task with no handler, so the dispatcher routed
everything to the fallback executor and the fallback reported success. Second,
**a guard written as a string match on the code it guards can rot into
asserting the absence of the code.** The reachability suite's negative control
injected the exact total break it was built to catch by replacing a literal
block of `can_handle` — and when `can_handle` lost its body, the injection
silently stopped matching, so the control reported "the break could not be
injected" and the suite failed at the wrong assertion. A negative control that
cannot inject its break is a negative control that has stopped testing anything.

The rule this yields: **the path that connects a caller to a handler needs its
own check, and that check must run the real thing out of process.** The
reachability suite does — a real subprocess, a real loopback socket, real HTTP,
and it asserts on an ON-DISK artifact the handler writes rather than on a return
value, so an in-process monkeypatch cannot make it green. It is now in CI, and
it is red whenever the wiring breaks.
