# Operator interface

This file is the contract between a one-word command and the learning loop.
The user never restates the methodology. `Learn XSS` is a semantic verb, and
this file says what it resolves to.

Load the `cyber-learning-orchestrator` skill before executing any of it. The
skill carries the loop; this file carries the command grammar.

## Command grammar

Every command resolves to a **Goal with falsifiable criteria**, then the same
loop. Criteria are counts and states, never adjectives.

| Command | Resolves to | First actions |
|---|---|---|
| `Learn X` / `Study X` / `Master X` / `Research X` | full loop on class X, from zero if unplanned | `wks.cli show X` (or `add-class`), `wks.cli gaps`, decompose, wave 1 |
| `Continue X` | resume an unfinished loop on X | read the last run record, find the open subgoal, dispatch the next wave only |
| `Review X` | audit X for gaps, contradictions, stale material, weak evidence | `wks.cli show X`, `python -m wks.verify_quotes --class X`, `gaps`, `taxonomy_write.py --check`, `python tools/audit_seed_subjects.py` (is every cited page ABOUT X?) |
| `Validate X` | evidence quality only, no new research | `python -m wks.verify_quotes --class X`, `gate`, `metrics`, cross-check publisher hosts |
| `Map X` | related classes, dependencies, chains | `retrieval` over X, `chains` table, chain docs in `chains/` |
| `Compare A and B` | structured technical comparison | `show A`, `show B`, diff the maturity vectors, name where the techniques genuinely differ |
| `Find gaps in X` | gap analysis only, no delegation | `gaps`, `tasks`, report the measured gaps as new subgoals |
| `Create methodology for X` | validated knowledge -> hunting procedure | `wks.methodgen`, then verify the generated steps each carry a disproof |

The word after the verb is the **learning target**. Resolve it to a
`bug_class.id` through `wks.cli show`, and if it is not registered, register it
with `add-class` before delegating anything — a child writing
`unknown class` in `item_key` gets its whole file rejected.

## The loop, in the order it always runs

```
GOAL (measurable criteria)
  -> CURRENT KNOWLEDGE ANALYSIS   what does the db already hold for X
  -> GAP ANALYSIS                wks.cli gaps / tasks, not intuition
  -> SUBGOALS                    each moves >=1 named criterion
  -> TASK DECOMPOSITION          one specialist job = one task = one file
  -> DEPENDENCIES                no unmet dep -> same wave
  -> DELEGATION                  waves of 2 (see rate limit below)
  -> RESEARCH                    read db/sources.json for X; search is bot-walled
  -> EVIDENCE COLLECTION         verbatim spans sliced from the fetched page
  -> CORROBORATION               >=2 DISTINCT PUBLISHER ORGS (not hosts)
  -> VALIDATION                  wks.ingest (the only writer of the corpus)
  -> SYNTHESIS                   regenerate the class page, chain, skill
  -> ORGANIZATION                one canonical home per class (R14)
  -> FALSE-POSITIVE ANALYSIS     fp_case rows, not fp_rule items
  -> MASTERY CHECK               the criteria, re-read from command output
  -> GAP ANALYSIS AGAIN          the loop does not end here
```

**Never stop because the research ended.** An exhausted budget becomes a new
subgoal. Termination is exactly two things: every criterion verified by a
command, or the user says stop.

## Where the loop reads sources from — ONE file

`db/sources.json` is the single source registry. It is GENERATED from the four
registries (`taxonomy._SEED`, `network_taxonomy._NET_SEED`,
`taxonomy_ext.CATALOG`, `research_sources.RESEARCH_SOURCES`) and is the only
place a source URL may come from.

**This is now true of the RESEARCH LOOP, not only of the briefing.**
MEASURED 2026-11-01 (Goal-chain audit): `orch/researcher.py::seed_sources`
iterated `taxonomy._SEED` in-process and never read this file, so the live
research loop and the brief that tells you what will be researched were
reading two different registries. They were in sync at the URL level, so no
wrong URL was produced — but the claim above was a documentation claim the
code did not honour. The research loop now reads this file, and falls back
to the corpus-derived `runtime/state/class-seeds.json` when it is absent.
`eval/test_researcher.py` R8 pins it behaviourally: it hides this file and
proves the loop does not fall back to a private curated list.

```bash
python -m wks.sourcebook <class_id>     # per-class worklist, text (paste into a brief)
python -m wks.sourcebook <class_id> --json
python -m wks.cli sourcebook <class_id> --rebuild   # regenerate, then brief
python tools/build_sources.py --check   # drift: registry vs the 4 registries
python tools/check_sources_parity.py    # independent parity (not a self-diff)
python tools/test_sourcebook.py          # adversarial safety tests
```

`db/sources.json` is a build artifact, so never hand-edit it (R11). Change a
registry, re-run the builder.

**`role` is load-bearing, not descriptive.** `role == "normative"` is the only
thing that counts toward `MIN_PUBLISHER_HOSTS`; `role == "lead"` NEVER counts,
however good the page is. A lead may be cited for technique, bypass, recon and
tooling, and `sourcebook.worklist()` returns the two buckets separately so a
caller cannot concatenate a blog post into a gate by accident (R20).

**Independence is `publisher_org`, not `host`.** `attack.mitre.org` and
`cwe.mitre.org` are one publisher (MITRE). Two pages on one organisation is one
publisher (R1).

Two known traps, both paid for:

- **Never invent or guess a URL.** Every legitimate URL is in the file. An
  invented one fails `verify_quotes.py` a wave later, after the work is done.
- **9 NETWORK classes were registered but could never promote.** Their seeds are
  `attack.mitre.org` + `cwe.mitre.org`, which collapse to one org. `seed.py`
  now counts publisher ORGS like `quality.py` does and SKIPS them with that
  reason, so a wave is never spent on unpromotable output. They stay in the db
  (seed skips, never deletes) and still need seeding from an independent
  publisher before they are worth assigning: `ad_ntlm`, `ad_delegation`,
  `credential_access`, `lateral_movement`, `pass_the_hash`, `password_attacks`,
  `segmentation_analysis`, `service_enumeration`, `tunneling_pivoting`.
  MEASURED 2026-10-31: that blocker has been cleared. All nine now carry
  promoted items backed by 6–11 distinct publisher hosts each
  (`ad_ntlm` 8, `ad_delegation` 9, `credential_access` 8, `lateral_movement` 8,
  `pass_the_hash` 8, `password_attacks` 6, `segmentation_analysis` 11,
  `service_enumeration` 10, `tunneling_pivoting` 8), so they are assignable
  work now, not waiting on a second publisher. The seed-skip guard stays in
  place for any class that regresses to a single org.

## Standing constraints

- **The database is canonical.** `classes/`, `chains/`, `skills/` and
  `bug-classes/` are projections. Edit rows, re-run the generator. Never
  hand-edit a generated file (R11).
- **One canonical home per class.** A second occurrence is a pointer stub with
  no content (R14). A vulnerability that appears in three chains still has one
  class page.
- **A URL is not evidence.** A quote is evidence. Two pages on one host is one
  publisher (R1).
- **A test that cannot fail proves nothing.** Every item carries a disproof
  (R4, invariant I3).
- **Validate the checker before trusting its verdicts.** Test the matcher both
  ways — a genuine span must PASS, a tampered span must FAIL — before
  reporting any rejection rate. A rejection rate from an unvalidated verifier
  is a measurement of your own bugs.
- **Waves of 2.** MEASURED on this host: a 4-child wave lost 3 children to
  HTTP 429. There is no fallback provider to absorb it.
- **Research only.** This system fetches published documentation. It does not
  scan, fuzz, or exploit anything (I6, R13).
- **A green suite proves the suite ran, not that the path is wired.** MEASURED
  2026-10-31: `ActiveHuntExecutor.can_handle` returned False for every key, so
  no hunt task ever reached a handler — while every suite reported green,
  because each one called a component directly. A hunt ran, exited 0 and gated
  14 candidate findings, all of them produced without a single probe. The
  dispatcher-to-handler path needs its own out-of-process check, and that check
  must inject its own break to prove it can still fail (I33).
- **A lock must not outlive its holder.** MEASURED 2026-10-31: a killed
  process left `wks-schema` held by a dead pid, and every writer in the
  project failed with `database is locked`. The reclamation that now breaks an
  abandoned lock reads the holder's pid, so it only works inside one pid
  namespace — a lock from another namespace is waited out, not stolen.
- **Opening the database is now restricted by default.** MEASURED
  2026-11-01 (Goal-chain audit): `wks.store.open_db()` defaulted to
  `owner=None`, which meant UNRESTRICTED — so the wks/orch ownership
  boundary was enforced only by `eval/test_ownership.py`, never by the
  running system. `open_db()` now defaults to the WKS owner: a raw
  `INSERT INTO finding` on a WKS connection is refused, and `INSERT INTO
  bug_class` succeeds. If your code genuinely needs to write across the
  boundary (a seed, a migration, a schema bootstrap), pass
  `unrestricted=True` — the call site then says so out loud. A sanctioned
  crossing of a single table is `@_ownership.as_owner(ORCH)` on the writer
  function, which is what `add_task` / `claim_task` / `finish_task` now
  carry.

## How to verify the whole thing

```bash
python eval/run_all.py            # every eval/test_*.py, per-file results
python eval/run_all.py --quick    # skip the slow repository-copy files
```

`run_all.py` discovers the suite rather than listing it, so a new
`eval/test_*.py` is picked up automatically and cannot be forgotten by a
hand-maintained list. The current state is **53/53 files passed** (full) and
**49/49** (quick).

Two checks are slow and are worth knowing about by name, because they are the
ones that catch defects no other suite can see:

| Check | Catches | Why it is separate |
|---|---|---|
| `eval/test_dispatch_reachability.py` | a hunt task that never reaches its handler | spawns the real CLI as a subprocess against a real loopback HTTP target, and asserts on an ON-DISK artifact the handler writes — never on a return value, so an in-process monkeypatch cannot make it green |
| `eval/test_migration_lock.py` | a lock that blocks every writer because its holder died | asserts BOTH directions: a live holder still blocks a second acquirer, and a dead holder is reclaimed |

R3 of the reachability check injects the exact total dispatch break it exists
to catch, by string-replacing `can_handle`'s body. If that injection ever
stops matching, the check fails at the injection step rather than silently
passing — a negative control that cannot inject its break has stopped testing
anything (I33).

### The eval suite must not write to the live corpus

```bash
python eval/test_p1_live_db_isolation.py   # 20 checks
```

The suite runs against the live canonical database by default, so a test that
opens the wrong one corrupts the corpus silently — and it PASSES, because the
live database has every table the test needs. That happened: 42 of the live
corpus's 46 `finding` rows and all 50 `lesson` rows were test output, and the
scheduler counted them as hunting impact.

This check makes the property verifiable rather than assumed. It covers the
in-process vector (`orch.store.open_db` takes no path, so a `Path` bound to
its `create` parameter silently opens the canonical database), the subprocess
vector (`WKS_ROOT` relocates the code too, so it cannot isolate a database
alone — `WKS_DB` can), and a BEHAVIOURAL CONTROL that runs a real eval file
and compares the live database's row counts before and after.

Two sandboxing levers exist, and they are not interchangeable:

| Variable | Relocates | Use when |
|---|---|---|
| `WKS_ROOT` | the whole tree, including the code | the run may use a different tree entirely |
| `WKS_DB` | ONLY the database | the run must execute the real code against a throwaway database |

### Quarantining test artifacts from the live corpus

```bash
python tools/quarantine_test_artifacts.py --dry-run
python tools/quarantine_test_artifacts.py
```

Under I8 nothing is deleted. The tool EXPORTS every matching record to
`superseded/test-artifacts-<timestamp>/` with a per-record verdict, then marks
the row `rejected` in place. What changes is what the system presents as live:
findings counted as potential impact, lessons returned as intelligence, and
the gaps and research proposals raised against them.

The exam harness's own findings (`exam-idor-*`) are deliberately NOT
quarantined. `wks/assess_evidence.py` creates them by importing a GRADED
EXAM, and `wks.quality` reads their evidence to decide what may be promoted.
They are the corpus's evidence base, not a leak.

### Measuring the corpus's evidence fidelity

```bash
python tools/audit_quotes_bulk.py --workers 12            # fetch once, judge all
python tools/classify_quote_drift.py --report <report>    # live vs archived
python tools/quote_fidelity.py     --report <report>      # paraphrase or invention
```

`wks.verify_quotes` is the reference verifier and it is correct, but it is
SEQUENTIAL and it keys its cache on `(url, quote)`, so a page cited by 40
items is fetched 40 times. MEASURED: a full-corpus run exceeded 900s and was
killed — which is why the corpus's fidelity was UNKNOWN rather than good or
bad. `audit_quotes_bulk.py` fetches each distinct URL once (922 URLs, 3,418
citations, ~4 minutes at 12 workers) and checks every citation against it.

**Read the result as three numbers, not one.** A citation that fails a
verbatim match is not automatically a fabrication:

| Verdict | What it means |
|---|---|
| present on the page | a verifier artefact, not a finding |
| in an ARCHIVED copy | the page was rewritten after the citation — honest, stale |
| near-verbatim paraphrase (>=90% tokens) | the meaning holds, the wording is not the source's |
| paraphrase (70-90%) | the meaning holds loosely |
| mostly absent or absent (<15%) | genuinely unsupported |

MEASURED 2026-10-31 over 335 failing citations: 69% near-verbatim or
paraphrase, 21% loose, **9.9% genuinely unsupported**. Calling all 335
"fabricated" would have been wrong, and would have pushed an operator into
rewriting a corpus that was never false.

**Do not run two corpus-wide audits at once.** They hit the same hosts, and
MEASURED, two concurrent runs drove each other's fetch success from 98.6%
down to 25% — the failure rate looked like a corpus defect and was pure
self-interference.

## Reporting

Report the Goal, the active subgoals, what was delegated, what was validated,
what was rejected and why, evidence quality, new relationships, remaining
gaps, and the next action. Name the command whose output proves each claim.

Never present a partial wave as a finished Goal. An unmet criterion named
plainly is worth more than progress that cannot be checked.

## Cycle priority (measured, not guessed)

Run `gaps` first. Then order the work by SCARCITY of each kind, not by class
name:

1. class has items but `fp_case` = 0  -> the highest-value item kind, because a
   false positive costs more than a missing technique
2. class has items but `chain` = 0
3. class has items = 0

`python -m wks.cli gaps` reports each class's `missing=` list (for example
`items,fp_rules` or `supported_items,fp_rules`); note that closing
`fp_rules` needs `fp_case` ROWS, not `fp_rule` items (`MATURITY_MIN_FP_RULES`
counts rows). Log them with `python -m wks.fp log --class ID`.
MEASURED 2026-10-31: this line previously showed the literal
`missing=fp_rules,chain`, which is not the format the command prints — the
`missing` column lists whichever capabilities the class actually lacks, and
`chain` is rarely among them because all 70 registered classes have at least
one chain step.
The `gaps` ordering and the research worker's queue are the same list, in the
same order (`eval/test_priority_maturity_reconcile.py` asserts it).

**Builder pages are not publishers** (R23): `app.notion.com`, `*.notion.site`,
`*.gitbook.io`, `*.readthedocs.io` and static hosts are filtered out of the
publisher count. Five such hosts are in the `source` table as leads; no active
item cites one.
