# R32 — the corpus's knowledge was mostly a template

Added 2026-10-02, recon refile/repair cycle. This is the deeper defect that
R29 exposed, and it is larger than misfiling.

## The measurement

While refiling the misfiled items, `tools/recon_refile.py` found a
DUPLICATE-bucketed row with no earlier twin and inspected it:

```
dns_enum.auto.01 (id 572)
CLAIM  : An XSS vulnerability may allow an attacker to execute arbitrary
         JavaScript code within the target's browser
BODY   : Easy
          11 Sections
          Reward: +10
          This module will take you step-by-step through the fundamentals
          of JavaScript Deobfuscation ...
DISPROOF: This is refuted if an authoritative source shows the described
           behaviour does not occur ... : "An XSS vulnerability may allow ..."
TOTAL ACTIVE COPIES: 13  (across 10 different classes)
```

A HackTheBox course-catalogue scrape. Its body is site chrome, its disproof
quotes the claim back at itself, and it was filed under `dns_enum`,
`ad_acl_abuse`, `ad_ntlm`, `ad_ldap`, `authn` and six more.

Corpus-wide (`python tools/recon_scraped_filler.py`):

```
active items                        1334
template disproof (refutes nothing)  586   (44%)
bodies carrying scrape chrome        124
claims appearing >1x                 355 rows in 112 groups
  spanning >1 class                  253 rows in 62 groups
```

**44% of the corpus carried a disproof that could not fail**, and R4 awards
0.30 of `technical_specificity` merely for HAVING a disproof. So a template
sentence bought a third of the specificity score while refuting nothing. That
is why the corpus read `mature` everywhere while teaching little.

## The rule

| # | Rule | Checked by | On failure |
|---|------|-----------|------------|
| R32 | A disproof must name a falsifying test for THIS mechanism. A fixed template, or a restatement of the claim, blocks promotion | `python -m wks.disproof --selftest` (12 cases, both directions); `python -m wks.disproof --audit`; the gate tags `BOILERPLATE_DISPROOF` / `CIRCULAR_DISPROOF` in `quality._BLOCKING_TAGS` | Replace the disproof with the real one. Never delete the item: the CLAIM is often sound, and only the disproof is hollow |

**Blocking, not rejecting.** A held SSRF mechanism sentence is real knowledge
that happens to carry a lazy disproof. The item is held for repair, and I5
forbids deleting it anyway.

### Two bugs found while building this

- **Brevity is not circularity.** The first version used a length floor
  (`MIN_USEFUL_CHARS = 60`) and flagged a legitimate 24-byte disproof in
  `eval/test_wks.py`'s dry-run canary — a real regression against a green
  suite. The test is now *substantive overlap*: does the disproof merely
  restate the claim? Both cases are locked in `SELFTEST`.
- **A gate may emit SEVERAL reasons for one item.** `eval/test_wks_relevance.py`
  asserted the persisted reasons *contained* `OFF_CLASS_TOPIC` and began
  failing intermittently once the disproof gate started adding a second tag to
  the same row. It now asserts that the item is held and that every reason
  produced was persisted. An intermittent gate test teaches the operator to
  re-run until green, which is worse than no test.

## The repair that was actually applied

Per I5 nothing was deleted. `tools/recon_refile.py` applied, in one
transaction:

```
refiled=28   deduped=44   rejected=60   kept=23
rows: total=1340 (unchanged -- I5 deletes nothing), active 1334 -> 1231
```

- **MISFILED (28)** moved class_id AND item_key together — the key's first
  segment IS the class, so a half-move yields a row whose key contradicts its
  class. Largest: `exposed_rmm` -> `authn` (15), `ldap_enum` -> `ad_ntlm` (4).
- **DUPLICATE (44)** pointed at a canonical twin via `dedup_of` and marked
  superseded. The **20 earliest copies** were NOT deduped: they have no
  earlier twin, so deduping them would have removed the origin. They were
  reclassified `DUPLICATE_EARLIEST` and rejected instead — that is where the
  HTB scrape was caught.
- **PROBE_FALSE_POSITIVE (23) kept unchanged.** These are correctly-filed
  items a vocabulary probe cannot see (SAML signature pinning under `authn`).
  Quarantining them would have deleted good knowledge — the exact error the
  audit was commissioned to find.

Projections regenerated per R11/R15: 142 taxonomy files, 62 SKILL.md, 60
COMPETENCY.md. `exposed_rmm`'s hunting skill now names RMM 11 times and
contains **zero** password-policy lines; previously password policy *was* its
entire content.

## Regression entry points

```bash
python -m wks.disproof --selftest     # R32, both directions
python -m wks.disproof --audit        # corpus-wide
python tools/recon_scraped_filler.py  # scrape chrome + template disproofs
python tools/recon_refile.py          # dry run; --apply to commit
python tools/recon_stable_measure.py  # R31: fail if the corpus moved mid-measurement
```