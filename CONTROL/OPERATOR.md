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
| `Review X` | audit X for gaps, contradictions, stale material, weak evidence | `wks.cli show X`, `verify_quotes --class X`, `gaps`, `taxonomy_write.py --check` |
| `Validate X` | evidence quality only, no new research | `verify_quotes --class X`, `gate`, `metrics`, cross-check publisher hosts |
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
- **9 NETWORK classes are registered but can never promote.** Their seeds are
  `attack.mitre.org` + `cwe.mitre.org`, which collapse to one org. `seed.py`
  now counts publisher ORGS like `quality.py` does and SKIPS them with that
  reason, so a wave is never spent on unpromotable output. They stay in the db
  (seed skips, never deletes) and still need seeding from an independent
  publisher before they are worth assigning: `ad_ntlm`, `ad_delegation`,
  `credential_access`, `lateral_movement`, `pass_the_hash`, `password_attacks`,
  `segmentation_analysis`, `service_enumeration`, `tunneling_pivoting`.

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

`python -m wks.cli gaps` reports `missing=fp_rules,chain`; note that closing
`fp_rules` needs `fp_case` ROWS, not `fp_rule` items (`MATURITY_MIN_FP_RULES`
counts rows). Log them with `python -m wks.fp log --class ID`.

**Builder pages are not publishers** (R23): `app.notion.com`, `*.notion.site`,
`*.gitbook.io`, `*.readthedocs.io` and static hosts are filtered out of the
publisher count. Five such hosts are in the `source` table as leads; no active
item cites one.
