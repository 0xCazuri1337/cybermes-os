# Session Report — WKS Cyber OS
**2026-10-04 · continuous learning loop · Hermes (lead) + OpenCode (worker) + 3-model deliberation**

All figures below were re-derived from `db/wks.db` and `runtime/loop/` at report
time. Nothing is carried forward from an earlier claim.

---

## 1. Headline numbers

| Metric | Value |
|---|---|
| Items in corpus | **1,693** |
| Promoted (`high_confidence`) | **1,083** (63.97%) |
| Held (`under_review`) | 610 (36.03%) |
| Disproof rate | **100.0%** (1,693/1,693) |
| Duplicate rate | 9.10% (154 groups) |
| Stale rate | 0.77% |
| Sources / publisher hosts | 822 / 150 |
| Registered publisher orgs | 124 (113 cited by active items) |
| Blocked on a single host | 180 |
| FP rules | 325 (`fp_case` 88 + `fp_rule` items 237) |
| Chains / chain segments | 79 / 48 |
| **Open conflicts** | **0** |
| Classes | 70 (55 mature = 78.57%) |
| Source access | ACTIVE 663 · BLOCKED 6 · UNVERIFIED 153 |

**New knowledge produced this session: 14 items** — 13 promoted, 1 held.
By origin: 8 from the aggregator harvest, 6 from autonomous research rounds.

---

## 2. Rubric: 95.0/100 — and why I am not claiming 100

| # | Total | Dimension | Score | Detail |
|---|---|---|---|---|
| 1 | 58.33 | baseline (first measurement) | — | four of my own scorer bugs |
| 2 | 76.67 | after fixing scorer bugs | — | +18.34 from measurement, not research |
| 3 | 10.0 | single-dimension probe | — | fp_control only |
| 4 | 80.0 | | | fp_control reached 10/10 |
| 5 | 85.0 | | | reasoning reached 20/20 |
| 6 | **95.0** | | | reproducibility + impact reached full |
| 7 | **95.0** | **immediate re-run** | | reproducibility check — identical |
| 9 | 95.0 | final | | stable across re-runs |

| Dimension | Score | Weight | Failing criterion |
|---|---|---|---|
| Source quality | 20.0 | 20 | — |
| Domain coverage | 15.0 | 20 | **dc2**: maturity 78.57%, needs ≥90% |
| Reasoning | 20.0 | 20 | — |
| Reproducibility | 15.0 | 15 | — |
| Impact / hunting usability | 15.0 | 15 | — |
| False-positive control | 10.0 | 10 | — |

**Score history is not a research curve.** Runs 1→2 (+18.34) and 4→6 (+15.0) came
mostly from correcting *my own measurements*, not from new evidence. Only the
harvest and research-round items moved the corpus. That distinction is why the
full history is in `runtime/loop/SCORES.jsonl` rather than just a headline number.

### The one remaining gap (dc2)
15 classes sit below the 12-item maturity threshold; **57 items** still needed.
Tightest: `otp` (1), `dns_enum` (2), `rate_limit` (2), `smb` (2),
`windows_privesc_token` (2). Reaching 90% of 70 classes = 63 mature, i.e. 8 more
classes over the line. This is genuine research volume, not a measurement fix.

---

## 3. Blocking defect found and fixed first

**Two layers, one table, incompatible status vocabularies.**

`wks` selected tasks with `status IN ('todo','doing')` and treated `done` as
terminal. `orch` owns the canonical vocabulary (`planned/ready/running/completed`)
and `orch/store.py::migrate_tasks()` rewrites the table on **every** orchestrator
open. So the moment the orchestrator had ever run, the knowledge engine could
not see a single task:

- `next_task()` returned `None`
- `wks.cli tasks` printed **"no runnable task"**
- the table held **18 claimable rows**
- `orch.cli stopcheck` simultaneously reported `ready: 18`

Two layers, same table, opposite verdicts, **no conflict raised**.

**Fix:** `wks/store.py` (`next_task`, `claim_task`, `finish_task`,
`normalise_task_status`) + `wks/overnight.py` (`select_tasks`) — accept the
canonical vocabulary plus the legacy names, since the table has no CHECK
constraint and either layer may write.

**Verification:** `eval/test_task_status_vocab.py` — 19/19, validated in **both
directions**, including negative controls (a child of a blocked / still-running /
non-existent dependency is still refused) and a reproduction of the original
defect on the old filter (old=1 row, new=2 rows). Gate re-baselined with a stated
reason; all 8 thresholds re-read **unchanged**.

---

## 4. Two-agent loop — 5 rounds, 2 produced

| Round | Result | Cause |
|---|---|---|
| 1 | exit 0, **zero work** | multi-line prompt via argv arrived as one line |
| 2 | 87s real work, then died | worker wrote to `%TEMP%`, permission-denied |
| 3 | 900s timeout, no artefact | spent the budget reading `wks/*.py` |
| **4** | **4 submitted, 4 promoted, 0 held, 0 rejected** | — |
| **5** | **2 submitted, 2 promoted, 0 held, 0 rejected** | — |

Three host traps, each of which **looked like success**:
1. npm installs three shims per binary; bash runs the `#!/bin/sh` one, native
   Windows Python raises `WinError 2`. Fixed by naming `opencode.cmd`.
2. A multi-line prompt via argv arrives as **only its first line** — the worker
   replied "Your message arrived as just the title", ran `ls`, and exited 0.
   Fixed by delivering the brief as a **file** with a one-line instruction.
3. `capture_output=True` + `TimeoutExpired` **erased 16 minutes** of the worker's
   output on timeout. Fixed by streaming to disk line-by-line.

A lesson worth keeping: **an exit code is not evidence.** The driver now asserts
the expected artefact exists before recording a round.

---

## 5. Multi-model deliberation — the highest-value output

Three distinct architectures (nemotron-3.5-lightning / ling-3.1-flash /
mimo-v2.6-flash), three lenses (advisory / standards / practitioner), on
`path_traversal`. **Claude Code 2.1.221 is installed but answers "Credit balance
is too low"** — so this is a genuine three-way debate, not a padded four-way one.

### A hallucination caught in one round
P1 claimed Windows `\.` "device name components" bypass `../`-filters by
"incrementing escape depth". P3 refuted it precisely:
- `\.` is a **no-op** segment, not a device name (CON/PRN/AUX/NUL/COM1 are)
- a no-op cannot add depth — only `..` does
- strip every `\.` and the payload resolves identically

Neither P1 claim may enter the corpus. A fluent, well-formatted, confident claim
was wrong on the mechanism.

### A high-confidence claim talked down
P3 asserted (confidence **high**) that traversal is provable from 403/404 status
codes. P2 and P1 both attacked it; **P3 retracted it itself**, naming the
confound: "logging, proxy rewriting, and error handlers can produce distinct
statuses with no file ever read."

Converged replacement, reached independently by all three lenses:
**confirmation requires content verifiably from outside the base directory.**

### My convergence metric was a false signal
First version reported **47 "convergences"** because it counted shared words like
`path`, `file`, `directory` — domain vocabulary, not agreement. With the class's
own vocabulary stop-listed:

| bar (distinctive shared terms) | pairs |
|---|---|
| ≥2 | 20 |
| ≥3 | 6 |
| **≥4** | **4** |
| ≥5 | 3 |

The 4 that survive are 2 real convergences + 1 contradiction. A metric that
cannot separate agreement from shared jargon reports a self-contradicting debate
as maximally convergent.

---

## 6. Hunting skills: the largest quality gain

**Measured gap:** `domains/web/path_traversal/skills/SKILL.md` renders 35
techniques of which **26 carry no action verb at all** — "By using special
elements such as `..` and `/` separators, attackers can escape outside of the
restricted location" is true and useless at 2am: no request to send, no comparison
to make, no observable to record. The skill's own "Hunt procedure" was 3
hand-written lines.

**Fix:** `tools/playbook.py` derives an executable procedure per promoted item by
classifying its *shape* (`http_param_probe`, `filter_bypass`, `encoding_ladder`,
`filesystem_sink`, `state_change`, `race_condition`, `blind_confirmation`).

**Result: 70 playbooks · 600 hunt entries · 0 without steps.**

Two bugs found while building it:
- **Item-authored steps outrank templates.** Items already state "Step: send X
  twice, once literal `../` and once percent-encoded". A `>=2 steps` bar
  discarded every one (they are written as *one* compound step), so a generic
  template silently replaced verified specifics. Bar is now `>=1`.
- **Never sentence-split on `.`** — my regex truncated "once with literal `../`
  sequences" to "once with literal ."

**Honest limitation:** 451/600 entries classify as `http_param_probe`. The
playbooks are procedural but not yet richly varied; templates need splitting by
technique family, not just shape.

---

## 7. Source added: bugbountydaily.com

Registered as `source_type='index'` — **discovery only, never citable**. The RSS
body is a bare list of links with no prose, so no quotable span exists on it; the
linked article is the publisher.

8 leads harvested → quote-verified against live bytes → paired with an
independent second publisher → **7 promoted, 1 held, 0 conflicts**.

Three bugs in my own harvest tooling: mapping keyed on raw hosts instead of
registrable domains (3 articles silently unmapped); host parsed with
`re.split(r"/+", url)[2]` (every article read as `UNMAPPED blog`); a 58-char span
accepted until a 90-char floor was added. Three partner URLs were 404 — two moved,
one wrong path — each replaced with a verified-live successor.

---

## 8. Knowledge persisted to `domains/`

`domains/` is the primary repository and **was already current**: 1083 promoted
items, **0 missing from any DIGEST, 0 from any SKILL**. What was missing is what
this session *built*:

| Artefact | Was | Now |
|---|---|---|
| 70 hunt playbooks | `runtime/` only | `domains/*/*/skills/HUNT.md` |
| 3 refuted claims | recorded nowhere | `domains/web/path_traversal/knowledge/refuted-claims.md` |
| Session decibels | session output only | 9 per-class notes in `knowledge/` |

The refuted-claims record matters most: losing it guarantees a future session
regenerates three refuted claims as if they were new.

### Three defects the verification gate caught
1. **`topics/` is not a registered subdirectory** — `domains.py` raises
   deliberately. Session notes landed there unroutable; moved to `knowledge/`.
2. **R11 makes hand-edits worthless.** I linked `HUNT.md` by appending to
   `SKILL.md`; `skills-sync --apply` regenerated the file and **silently stripped
   both links**. Fixed in the generator (`wks/skillgen.py`) — links are emitted
   only when the target exists, so a dangling link is impossible.
3. **My "touched classes" list was a guess** — named 3 classes never touched,
   missed 5 that were. The gate now derives it:
   `SELECT DISTINCT class_id FROM item WHERE created_at >= ?` → **10 classes vs my
   guess of 8**.

---

## 9. Session verification — PASSED (7/7)

```
V1  all 1083 promoted claims present in their DIGEST      0 missing
V2  all 1083 promoted claims present in their SKILL       0 missing
V2b every class routes to a domain folder                 0 unroutable
V3  every class with evidence has a HUNT.md runbook       missing: []
V4  every SKILL.md links its HUNT.md                      unlinked: []
V5  every session-touched class has a domain note         no record: []
V6  no conflict open without a recorded resolution        0 unresolved of 3 open
V7  projections idempotent (re-run writes nothing)        changed: []
```
Reproduce: `python tools/verify_session.py`

---

## 10. Gate integrity

`wks.cli selftest` → **ALL WKS GATE TESTS PASS**.

`eval/test_gate_refuses_fabrication.py` → **10 pass, 0 fail**. Nine fabrications
refused: quote not on the cited page, same-publisher pair, single source as two,
boilerplate course-catalogue text, four invented cross-references (`Ref1`,
`Source2`, `N/A`, `placeholder`), truncated fragment. The genuine control is
accepted — a gate that refuses everything would pass every case and be useless.

### Known gate gap (documented, not hidden)
**The gate does not check quote→claim entailment.** It verifies a quote *exists*
on the cited page and that two publishers are *independent*. It does not verify
the quote *supports* the claim's mechanism: two verbatim-but-definitional quotes
promote a mechanism claim at score ~0.80. Left in the suite as a `KNOWN_GAP`
rather than deleted — deleting it would restore a green run that hides a real
weakness.

---

## 11. Defects found in my own work this session

| # | Defect | How it was caught |
|---|---|---|
| 1 | task-status vocabulary split | `next_task()` returned `None` over 18 rows |
| 2 | multi-line prompt via argv | worker exited 0 having done nothing |
| 3 | timeout erased worker output | `worker-output.txt` = 18 chars |
| 4 | concurrent runs clobbered files | two debates overwriting each other |
| 5 | "reply with JSON" → permission-denied write | model wrote `/tmp/claims.json` |
| 6 | `rm -rf` on a live round dir | `FileNotFoundError` mid-round |
| 7 | convergence metric counted jargon | 47 "convergences" for a contradicting debate |
| 8 | `1/1 cross-examined` on a killed round | denominator was files-that-existed |
| 9 | 4 scorer bugs (`item.item_id`, `claimcheck.audit`, `retrieval.retrieve`, `s_host.host`) | reported gaps that did not exist |
| 10 | `rs3` blamed the corpus for what the gate already held | 37 course-prose items, 0 promoted |
| 11 | `im2` counted only `fp_case`, never `fp_rule` items | 4 items promoted, metric moved by zero |
| 12 | host parsed with `re.split(r"/+", url)[2]` | every article `UNMAPPED blog` |
| 13 | session notes in unregistered `topics/` | `domains.py` raised deliberately |
| 14 | hand-appended link stripped by projection | V7 idempotency failure |

**Ten of fourteen were measurement or harness defects, not knowledge defects.**
That ratio is the most useful thing in this report.

---

## 12. Open items

| Item | State |
|---|---|
| **dc2** — 15 classes below maturity, 57 items needed | open; needs real research volume |
| Gate entailment check | open; no component exists |
| Playbook shape concentration (451/600 one shape) | open; templates need family-level split |
| 7 harvest items carry topic-label claims | open; mechanism + disproof in body only |
| `mass_assign.lead.bbd_varonis.com` | held `OFF_CLASS_TOPIC`; left refused deliberately |
| 3 open conflicts | all with recorded resolutions (V6) |
| 153 sources UNVERIFIED | `access_state` never measured |
| Claude Code as 4th debater | blocked on credit |

## 13. Backups
`db/wks-pre-statusfix-*`, `wks-pre-loop-*`, `wks-pre-wave2-*`, `wks-pre-r5-*`,
`runtime/backup-domains-*`.

## 14. Reproduce this report
```bash
export WKS_ROOT="C:/Users/Administrator/.hermes/cyber"
cd "$WKS_ROOT"
python -m wks.cli metrics
python -m wks.cli selftest
python eval/score_rubric.py
python eval/test_gate_refuses_fabrication.py
python tools/verify_session.py
cat runtime/loop/SCORES.jsonl
```