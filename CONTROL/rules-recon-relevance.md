# R29 / R30 — added 2026-10-02 (Recon mastery cycle)

These two rules close the largest measured source of false mastery in this
corpus. Both were found by auditing rather than by a failing test, which is
why they needed writing down: nothing was red before they existed.

| # | Rule | Checked by | On failure |
|---|------|-----------|------------|
| R29 | No item is promoted when its claim is about a DIFFERENT class, or is course prose | `python -m wks.relevance --selftest` (67 cases, both directions); `python -m wks.relevance --audit`; `python eval/test_wks_relevance.py` T22 | Fix the FILING or the CLAIM, never the threshold. `MISFILED_SCORE` may be widened only while `TERMINAL_STATES` stays positive-evidence-only |
| R30 | A subagent that touches the corpus must open it through `wks.readonly`, never a relative path | `python -m wks.readonly --selftest` | A relative `sqlite3.connect('db/wks.db')` silently resolves against the process CWD and MUTATES or CREATES the file. Restore from the snapshot and switch to `ro()` / `sandbox()` |

## Why R29 exists, with the measurement

Before this rule the gate verified **provenance** and never **subject**: is the
quote real, is it on the cited page, do two publisher orgs corroborate it. All
three passed for a sentence about OWASP password policy filed under
`exposed_rmm` (Remote Monitoring and Management Abuse), because provenance says
nothing about what a sentence is *about*.

Measured on the live corpus before the fix:

```
items_total 1111   items_by_state {high_confidence: 1111}   promotion_rate 100.0%
```

Every class reported `mature`. Then, measured after wiring the subject gate into
`quality.assess` and re-running `python -m wks.cli gate`:

```
items_total 1111   items_by_state {high_confidence: 888, under_review: 223}
promotion_rate_pct 79.93   unsupported_claim_rate_pct 20.07
de-matured classes 23
gate_reasons on demoted items: 172 OFF_CLASS_TOPIC, 51 MODULE_FILLER
```

Worst classes before → after (`exposed_rmm` 82.6% off-topic, `dns_enum` 63.6%,
`service_enumeration` 71.4%):

| class | items | high_confidence after |
|---|---|---|
| exposed_rmm | 23 | 9 |
| ad_enumeration | 22 | 10 |
| dns_enum | 22 | 10 |
| exposed_services | 21 | 9 |
| ad_ldap | 21 | 10 |
| segmentation_analysis | 20 | 11 |
| ad_ntlm | 21 | 9 |

### The rule that keeps R29 from becoming the quote matcher

`wks/quality.py` warns that matching a raw reason string is a trap
(`FABRICATED_REFS(4)` != `FABRICATED_REFS`), and R29 nearly repeated it: the
verdict STATE is `MISFILED` but the gate TAG is `OFF_CLASS_TOPIC`. Appending
`rel.state` produced reasons the gate silently ignored — 13 of 14 held
`exposed_rmm` items stayed `high_confidence` while *looking* held to anyone
reading the relevance output. Always append `rel.tag`, and
`test_wks_relevance.py` T22a asserts that string is present in the source.

### Absence of vocabulary must NEVER block

The first draft added an `ORPHAN` state ("no class matched") to
`TERMINAL_STATES`. Measured, that branch was **~70% false positive**: its 117
held items included textbook SQLi, XSS, path-traversal, IDOR and race knowledge
("Two concurrent read-modify-writes on a balance or quantity field let one
thread's write silently clobber the other's") that simply phrased itself without
a registry token. `ORPHAN` now annotates and feeds vocabulary repair.

So the terminal states are `MISFILED` and `MODULE_FILLER` only — both
**positive** evidence (another class explains the claim clearly; the claim is
syntactically course prose). `ON_TOPIC`, `SIBLING`, `AMBIGUOUS` and `ORPHAN` are
reported and never block. `wks.relevance.selftest()` asserts this as an
INVARIANT over the whole battery, not as a case list, so adding an `ORPHAN` case
cannot silently make it terminal again.

Two further measured bugs from building it:
- a sibling-class rule is mandatory: `rdp` and `exposed_services` both describe
  an exposed RDP port, so an RDP-flavoured sentence under `exposed_services` is
  overlap, not misfiling, and holding it is a false positive on correct knowledge
- punctuation-only terms (`"../"`) extract no tokens from `[a-z0-9]+`, so a
  tokenizer-only matcher can NEVER match them; they are matched literally

## Why R30 exists

MEASURED during this same cycle: a subagent briefed "read-only against the db"
ran

```python
sqlite3.connect('db/wks.db')                 # relative path
c.execute("DELETE FROM item_source WHERE item_id IN (SELECT id FROM item WHERE class_id='idor')")
```

intending a sandbox. A relative path resolves against the process CWD, and
`sqlite3.connect()` on a writable path creates or mutates the file — sqlite does
not refuse. Five `ldap_enum` rows were flipped to `superseded`. No rows were
lost and the state was restored by diffing against `db/wks-pre-resynth-*.db`,
but a child probed the gate on live data it was told not to touch.

A brief saying "read-only" is not a control. `wks.readonly.ro()` opens
`mode=ro`, where the first write raises `attempt to write a readonly database`;
`wks.readonly.sandbox()` returns a marked private copy. Both directions are
proven by `python -m wks.readonly --selftest`.

## Regression entry points

```bash
python -m wks.relevance --selftest        # R29, 67 verdicts, both directions
python -m wks.relevance --audit           # R29, corpus-wide hold report
python eval/test_wks_relevance.py         # R29 WIRING (R19): the call path
python eval/test_relevance_negative.py    # R29 negative control: must go red
python -m wks.readonly --selftest         # R30
python tools/recon_verify_children.py     # delegated output vs the db
```

Run all of them before claiming a cycle improved anything. A green
`test_wks_relevance.py` on its own proves only that the assertions hold — the
negative control is what proves they can fail.