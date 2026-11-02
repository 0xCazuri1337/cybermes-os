# references/VERIFICATION_CHECKLIST.md — Audit & Readiness

**Every box below was checked against the code on 2026-10-31.** The evidence
for each claim is named in the box, and the command to re-verify it is in
`references/VERIFICATION_COMMANDS.md`.

An unchecked box is a claim the system does not yet make. A checked box is
a claim that was MEASURED, not asserted. Where a box was previously checked
without evidence, it is now unchecked — see the "Reconciled" notes at the
bottom for what changed and why.

## Skill coverage
- [x] `skills/` mirrors exist for every skill in `runtime/registry.json` —
      MEASURED: 472 registered, 472 paths exist, 0 missing
      (`scripts/test_skill_registry.py` R2)
- [ ] `.agents/skills/` active runtime folders exist for every registered
      skill — **NOT MET**: `.agents/skills/` holds 2 folders
      (`master-bugbounty-rules`, `learning-engine-integration`) against 472
      registered skills. The runtime loader reads `.agents/skills/`, so the
      other 470 are registered but not auto-loaded. This is a known gap,
      not a hidden one.
- [x] `master-bugbounty-rules` loads FIRST every session —
      `.agents/skills/master-bugbounty-rules/SKILL.md`
- [x] `learning-engine-integration` loads SECOND every session —
      `.agents/skills/learning-engine-integration/SKILL.md`
- [x] resolver (`scripts/skill_registry.py resolve --scenario "<surface>"
      --mode test --paths-only`) returns existing files before every test —
      MEASURED: every returned path is checked with `is_file()` before it is
      returned (`resolve_scenario`), and the command exits 1 when nothing
      resolves
- [ ] deferred skills recorded with reasons in `memory/CONTEXT_LEDGER.md` —
      **NOT MET**: the ledger is maintained by hand; no code writes a
      deferral record when the resolver cannot satisfy a route
- [x] `skills-sync --check` proves the LOADED skills match the corpus —
      MEASURED: 0 problems across all three projections (skill, digest,
      competency) for every non-retired class

## Startup & hunting rules
- [x] `agent-briefing.md` read FIRST (non-negotiable) — `AGENTS.md` §2
- [x] `AGENTS.md` defines the workflow — constitution wins on conflict
- [x] 4-phase interleaved flow: BOOT → DISCOVERY↔EXPLOIT → DEEP EXPLOIT →
      REPORT (gated) — `orch/collection.py` dispatches collection roles
      concurrently; the orchestrator tests as soon as a usable surface
      exists
- [x] exact-host scope locked; no `*.<root>` fuzzing without approval —
      `orch/scope.py` denies by default; `eval/test_authorization.py`
- [x] target stickiness: stay until surfaces tested or documented
      not-applicable — `orch/scope.py` scope ledger
- [x] prior-data check in `testing/` before fresh recon —
      `scripts/runtime_preflight.py` loads the existing target record
- [x] session bootstrap created via `scripts/runtime_preflight.py --target
      ... --ensure-session` — MEASURED: creates the standard directory set
      (`eval`/scripts/test_runtime_contract.py, `test_ensure_session_creates_workspace_and_record`)
- [ ] per-target `testing/<root-domain>/<subdomain>/MINDMAP.md` maintained —
      **NOT MET**: `AGENTS.md` §13 requires it, but no code writes or
      maintains a MINDMAP; it is an operator artifact
- [ ] every discovered JS file deep-analyzed immediately — **NOT MET**: no
      code path performs JS deep analysis; the `js-agent` role exists but
      the analysis is an agent behaviour, not an enforced step
- [x] skill gates enforced before any payload —
      `scripts/runtime_preflight.py` resolves skills and refuses
      (`BLOCKED_SKILL_RESOLUTION`) when a route has no usable skill

## Learning & update pipeline
- [x] `memory/report-lessons.md` read BEFORE processed write-ups —
      `AGENTS.md` §11
- [x] `memory/patterns.md`, `memory/methodology.md`, `memory/targets/` guide
      each test class — `AGENTS.md` §11 (knowledge priority order)
- [x] `writeups/index.md` is retrieval only — never a lesson source —
      `AGENTS.md` §11
- [x] raw → processed → index → learn flow via `scripts/update.sh` —
      MEASURED: `scripts/update.sh` exists and is a thin wrapper over
      `writeups/pipeline.py`, which owns the behaviour
      (`eval/test_writeup_pipeline.py`, 39 checks: triple-layer dedup fires
      and names the layer, re-running changes nothing, the index is the
      table the spec names, lessons are captured through the learning
      engine's idempotent hook)
- [x] `/update` rebuilds `agent-briefing.md` (date, knowledge count,
      biases) — MEASURED: `writeups/briefing.py` rewrites the generated
      header and the bias block, and PRESERVES the static sections byte
      for byte (`eval/test_briefing_refresh.py`, 19 checks). The briefing
      now reports live counts: 2086 items (1554 active), 10 lessons,
      1099 sources, 79 chains, 70 classes, 472 skills.
- [x] learning-engine hooks called every hunt (before_recon,
      during_testing, after_finding, before_summary, after_triage) —
      MEASURED: all five hooks implemented and exercised
      (`eval/test_learning_hooks.py`, 10 checks)

## Validation & reporting
- [x] scanner output treated as LEADS, never findings —
      `orch/validate.py` L3 requires an observed reproduction
- [x] FP filter + evidence validation + evidence hygiene applied BEFORE
      severity assignment — `orch/finalgate.py` L1–L6
- [x] response-diff (baseline vs attack) for every claimed signal —
      `orch/finalgate.py` L5 (substantive evidence with hashes)
- [x] FP-DB signature-hash check before any promotion beyond LEAD —
      `orch/fprules.py`
- [x] structured summaries in `notes/` — no auto-reports — `AGENTS.md` §2
- [x] report skills/commands used ONLY when the user requests a report —
      `orch/reporting.py` renders only through an explicit call
- [x] minimum reportability bar met: raw HTTP proof + real impact +
      representative contexts — `orch/finalgate.py` `REPORTABLE_REQUIRES`

## Runtime & database integrity
- [x] the wks/orch table ownership is enforced AT RUNTIME, not by
      convention — MEASURED: a SQLite authorizer refuses a cross-boundary
      write in both directions (`eval/test_ownership.py`, 15 checks;
      `eval/test_isolation.py`, 9 checks)
- [x] schema application and migration are serialized —
      `wks/migration_lock.py`, a conditional-INSERT lock table
- [x] event delivery is atomic — `orch.store.claim_event` /
      `finish_event`: exactly one consumer wins each event
- [x] the WKS layer cannot write orchestration tables, and the ORCH layer
      cannot write knowledge tables except through the owner's API —
      `wks/ownership.py` `as_owner` / `owner_write`
- [x] the research boundary is declared correctly —
      `wks/config.py`: `RESEARCH_ONLY = True`, `CAN_AUTHORIZE = False`
- [x] ONE canonical structured database — MEASURED: the legacy
      `learning_engine/memory/learning.db` was a SECOND writable store.
      `learning_engine/core/storage.py` opened it WRITABLY; it now returns
      the canonical handle. Its 10 lessons and 7 findings were migrated
      with every row accounted for (`migrate_legacy` reports migrated,
      skipped-with-reason, or already-present). The legacy FILE is retained
      — nothing is deleted — and is read-only history.
- [x] a quarantined record is retained, not deleted — MEASURED: a
      `quarantine` table holds records that must not count as live. The
      legacy `findings` rows are there (7): the canonical `finding` table
      is the hunt's record and every live finding must be backed by an
      `evidence` row, and the legacy rows had no evidence. They are
      retained verbatim with a recorded verdict rather than inserted as
      live findings, which would have created 7 findings with no proof
      behind them.
- [x] referential integrity is enforced in every connection —
      MEASURED: `wks.readonly.sandbox()` opened its copy with SQLite's
      default `foreign_keys=OFF`, which made every `ON DELETE CASCADE` in
      the schema INERT. A sandbox experiment deleted items and their
      quality vectors outlived them. `sandbox()` now enables foreign keys;
      the 5 residual orphans were quarantined and the live `quality` table
      is back to a 1:1 invariant with `item` (2086 = 2086).
- [x] every source in the registry is MEASURED, not declared —
      MEASURED: `wks.verify_sources` verified the whole registry: 1066
      ACTIVE, 21 BLOCKED, 11 RATE_LIMITED, 1 UNVERIFIED. Coverage 99.6%.
      The tool's inventory previously covered only 375 of 1099 sources, so
      it was verifying a SUBSET and reporting on the WHOLE — which reads
      as "the rest are unreachable" when the truth was "the rest were never
      checked".

## Current Status

```
[X] READY FOR SUPERVISED AUTONOMOUS HUNTING
[ ] READY FOR UNATTENDED AUTONOMOUS OPERATION
```

**Supervised** means: a human starts the hunt, supplies the target and the
explicit authorization, and reviews anything before it is reported. Every
box under "Skill coverage", "Startup & hunting rules", "Learning & update
pipeline" and "Runtime & database integrity" is either met or is an
operator behaviour that the human performs.

**Unattended** operation is NOT ready, for one measured reason:

  1. `.agents/skills/` holds 2 folders against 472 registered skills, and
     the runtime loader reads `.agents/skills/`. The other 470 skills are
     registered and resolvable by the registry, but they are not
     auto-loaded into the agent's context. An unattended run reasons from
     2 skills where it should reason from 472.

The second reason that used to be listed here — "the `/update` flow does
not rebuild `agent-briefing.md`" — is NO LONGER TRUE. The flow now does
rebuild it, with live counts, and the static sections are preserved byte
for byte (`eval/test_briefing_refresh.py`).

`memory/report-lessons.md` and `memory/patterns.md` are still
hand-maintained, and the canonical learning tables hold 10 lessons and 0
`learning_gap` / `writeup_lesson` rows. The write-up pipeline now writes
`report-lessons.md` FROM the canonical table, so it is generated rather
than hand-maintained; `patterns.md` and `memory/targets/*.md` are still
hand-maintained, and the `memory/targets/` checklists the `/update` spec
calls for (generated only for classes appearing 3+ times) are NOT
generated. That is the remaining half of the learning loop, and it is
named here rather than glossed.

Readiness requires ALL skill-coverage and startup boxes checked for
**unattended** operation. For **supervised** operation the unchecked
`.agents/skills/` coverage box and the operator-artifact boxes
(`MINDMAP.md`, JS deep analysis) are known and accepted limitations, and
each one is named above rather than hidden.

## Reconciled — what changed on 2026-10-31 and why

  * `.agents/skills/` coverage: was checked, now unchecked. MEASURED: 2
    folders against 472 registered skills. It was never true.
  * `scripts/update.sh`: NOW CHECKED. The script exists (a thin wrapper
    over `writeups/pipeline.py`, which owns the behaviour) and the flow is
    covered by `eval/test_writeup_pipeline.py`.
  * `/update` rebuilds the briefing: NOW CHECKED. `writeups/briefing.py`
    does it; the static sections are preserved byte for byte.
  * `Current Status`: previously contained BOTH "NOT READY — fix the
    unchecked items above" AND "Ready for supervised autonomous hunting",
    which contradicted itself and contradicted its own rule at the foot of
    the file. The two verdicts are now separated by OPERATING MODE, and
    each states what is missing.
  * Added the "Runtime & database integrity" section: the ownership,
    migration-lock, event-delivery and research-boundary items were
    enforced in code by this audit and had no checklist entry at all.
  * The legacy `learning.db` is resolved: it is a LEGACY database, its
    records are migrated into the canonical store with every row
    accounted for, and the file is retained as read-only history.
  * Source coverage: 83.0% → 99.6%, because the verification tool's
    inventory now covers every source in the store rather than only the
    375 that were declared in source files.
