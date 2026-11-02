# Engineering Report — WKS Cyber OS
**2026-10-04 · Hermes (Lead Architect) + OpenCode (Deputy/Adversarial Reviewer) · Phase 1–4 delivered**

Every number below was re-derived from `db/wks.db` or a test run at report time.

---

## 1. What was wrong

**Two baseline numbers in the mission brief were wrong.** Checked against the
implementation before touching anything:
- items: reported **1693**, actual **1817**
- conflicts: reported **0**, actual **184 rows** (151 dismissed, 30 resolved, 3 open)

The conflict figure is the interesting one. `wks.cli metrics` counted only
`status='open'`, which is *correct for what it counts* and useless for what a
reader infers — "0 conflicts" reads as "conflict handling is healthy" to anyone
who doesn't query the db. Underneath it sat 3 genuinely open rows (all carrying
resolutions) and 181 historical ones.

**The hunting-skill collapse had a specific root cause**, not "not enough
templates": `tools/playbook.py::classify()` returns a RANKED list of matching
shapes, and only `[0]` was ever consumed — while the `http_param_probe` regex
matches any HTTP-ish word. 451 of 600 entries (75%) landed there. The deeper cause
was that the model had ONE axis (shape) where real hunting varies along seven.

**`wks/skillgen.py` had no variation model at all** — it renders promoted items
by `kind` and stops.

---

## 2. What Hermes proposed

| # | Proposal |
|---|---|
| P1 | A **variation model**: 7 axes (request_location, encoding_layer, auth_state, transport_path, parser_differential, app_state, confirmation), every value carrying a **probe** (what to do) and an **observe** (what to look at), detected from each item's own text |
| P2 | An evidence **entailment** check on the gate |
| P3 | Multi-dimensional `dc2` coverage (existence/evidence/procedural/operational/FP) |
| P4 | Keep `orch` as commander, `wks` as deputy; no module re-parenting |

## 3. What OpenCode challenged

The reviewer confirmed all three of my diagnoses with independent evidence, then
attacked the proposals:

| Proposal | Verdict | Sharpest criticism |
|---|---|---|
| P1 variation | **unsound-as-stated** | "7 templates with 451 cosmetic variants is not variation" — and critically: *audit_variation can pass while every entry still emits identical steps* |
| P2 entailment | **unsound as a promotion gate; sound as a downgrade signal** | Lexical entailment is keyword overlap, and a claim plus a definitional quote share vocabulary *by definition*. Would pass everything or reject legitimate findings "with false authority" |
| P3 multi-dim dc2 | **unsound as a direct replacement** | A class can tick "existence" and "evidence" boxes with zero procedural depth — "the number goes up while actual capability goes down", and it's *harder to detect* than the old count |
| P4 orch/wks split | sound from governance, **unsound without vocabulary alignment** | Two parallel taxonomies (7 templates vs 7 axes) with no mapping between them = the same split, relocated |

Its top-3 targets: integrate variation into skillgen (720), use the full
ranked list + tighten the regex (518), fix conflict counting (360).

## 4. What changed

**Implemented:**
- `wks/variation.py` (new, ~300 lines) — the 7-axis model, `detect_axes`,
  `variation_block`, `escalation`, `audit_variation`
- `wks/evalm.py` — conflict metrics now report the whole population
- `tools/playbook.py` — wired to the variation model; `--all` bulk mode that
  routes by the db and clears stale duplicates
- `tools/write_hunt_docs.py` — calls `--all` (was calling a no-arg invocation
  that exited 2 and silently regenerated nothing)
- `eval/test_variation.py` (new) — 25 checks, both directions
- 70 `domains/*/*/skills/HUNT.md` regenerated with variation + escalation

**The reviewer's P1 attack was correct and I fixed it rather than defending it.**
The first `audit_variation` only counted distinct *axis combinations*. The
reviewer predicted that 451 distinct-label/identical-step entries would pass.
It would have. The audit now maps each entry to the exact instruction strings it
emits, and **T8 constructs that precise gaming case and asserts it is REJECTED.**

**Rejected after review:** P2 (entailment). The reviewer is right — without an LLM
it is keyword overlap, and a binary gate would be worse than none. Recorded as a
bounded known gap with the reasoning, not implemented as a gate.

**Deferred:** P3 (multi-dim dc2). Valid criticism that it invites new gaming; not
attempted in this pass rather than half-built.

---

## 5. Domain improvements

- 70 playbooks regenerated; duplicates eliminated (`web-<cid>.json` vs
  `network-<cid>.json` — the `--all` writer hardcoded `web`, so 30 classes were
  being written under the wrong domain prefix while a stale file won downstream)
- `domains/*/*/skills/HUNT.md` now carry per-entry variation + escalation

## 6. Hunting improvements

| Metric | Before | After |
|---|---|---|
| Hunt entries | 600 | 600 |
| Distinct variation profiles | (not measured) | **162** |
| Distinct INSTRUCTION sets | (not measured) | **162** |
| Dominant share | **75.2%** (451/600) | **22.3%** |
| Playbooks passing anti-gaming audit | n/a | 67/70 |

Sample (`path_traversal.bypass.percent_encoding_normalization_defeats_allowlist`):
axes `{encoding_layer: url, parser_differential: front_back, confirmation:
differential}` → "do send it percent-encoded once; observe whether the decode
happens before or after validation" + "do front end filters, back end parses;
observe a request the front end 'cleared' but the back end acted on".

## 7. Maturity improvements

**None this pass.** Maturity is unchanged at 55/70 (78.57%) — no new corpus items
were produced; this phase was architecture and measurement. Stated plainly rather
than dressed up.

## 8. Coverage improvements

`dc2` still fails. No coverage number moved, and I am not claiming one did.

## 9. Reliability improvements

- Bulk playbook regeneration was a **silent no-op**: `tools/playbook.py` with no
  args hit its usage branch and exited 2, `write_hunt_docs` saw rc=0, and reported
  "0 written" while every playbook stayed stale. Fixed with an explicit `--all`.
- `--all` now routes by `class_domain` instead of hardcoding `web`, and deletes
  stale cross-domain duplicates.
- `evalm.metrics` no longer presents `open_conflicts: 0` without context.

## 10. Verification

```
eval/test_variation.py                    25 pass, 0 fail
eval/test_task_status_vocab_v2.py         all checks passed
eval/test_gate_refuses_fabrication.py     10 pass, 0 fail (1 KNOWN_GAP documented)
tools/verify_session.py                   7/7 PASSED
wks.cli selftest                          (in progress at report time)
```

New tests, each able to fail:
- T8 rejects 50 entries with 4 distinct axis profiles but **1** instruction set
- T4 rejects 50 identical-axis entries
- T2 an item mentioning nothing gets the honest default, no invented variation
- T7 escalation names when to STOP ("a flat result is a result")

Bugs these tests caught in my own new code: double-encoding mis-detected as single
(`"twice percent-encoded"` contains `"percent-encoded"`), and the encoding ladder
being offered only when nothing was detected — backwards, since a `url` payload
has not tried the other rungs.

## 11. Remaining weaknesses

1. **dc2 unchanged** — 15 classes below maturity, 57 items needed.
2. **3 playbooks fail the anti-gaming audit honestly**: `container_escape`
   (4 entries, 1.0 share), `windows_privesc_token` (3, 1.0), `race` (8, 0.625).
   These items genuinely describe one mechanism family, so detection-from-text
   yields one profile. Real, not a bug — fixable only with more items.
3. **15 classes have <3 entries** — variation is unassessable, reported as such.
4. **Gate entailment still unenforced** — now bounded and documented rather than
   silently absent.
5. **Variation is text-detected**, so two items describing the same mechanism in
   different words can still land on different profiles.
6. `skillgen.py` still does not itself render variation — HUNT.md carries it.

## 12. Next highest-value improvement

**Integrate the variation model into `wks/skillgen.py` so the primary SKILL.md is
itself dimension-aware** — the reviewer ranked this 720 (impact 10 × breadth 10 ×
persistence 9). Today variation lives only in the HUNT.md runbook; a hunter who
opens SKILL.md still sees 26-of-35 techniques with no action verb. After that,
attack dc2 with real research volume rather than more measurement work — five
further rounds of measurement fixes have now produced zero corpus items, which
is the honest signal that the measurement phase is done.