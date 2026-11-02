# GAP-FILL REPORT — rdp, ad_group_policy, csrf, bizlogic

Date: 2026-10-02 (Africa/Cairo)
Repo: `C:/Users/Administrator/.hermes/cyber`
Snapshot: `db/wks.db.bak-20261002-150914` (row counts asserted equal on the copy)

## 0. The premise in the brief was wrong — the classes were not empty

The task described these four classes as having **ZERO gated items**. Measured at the
start, before any write:

| class | items (pre) | supported | fp | chains | state | reported `missing` |
|---|---|---|---|---|---|---|
| rdp | 9 | 9 | 1 | 0 | researching | items, fp_rules, chain |
| ad_group_policy | 11 | 11 | 2 | 0 | researching | items, chain |
| csrf | 5 | 5 | 3 | 0 | researching | items, chain |
| bizlogic | 5 | 5 | 4 | 1 | researching | items |

No class was empty. The real gap was the **maturity** definition
(`wks/quality.py:maturity()`): `items >= 12`, `supported >= 4`, `fp_rules >= 2`,
`chains >= 1`. This is reported, not worked around — no threshold was changed, and
`wks/config.py`, `wks/quality.py`, `wks/schema.sql`, `wks/taxonomy.py`,
`wks/store.py` were **not edited** (selftest's fingerprint self-audit passes).

## 1. Outcome per class

| class | declared | attempted | promoted | items (post) | fp | chains | state |
|---|---|---|---|---|---|---|---|
| rdp | 1 | 6 | 6 | 15 (+6) | 3 | 1 | **mature** |
| ad_group_policy | 1 | 2 | 2 | 13 (+2) | 2 | 1 | **mature** |
| csrf | 1 | 11 | 11 | 16 (+11) | 4 | 1 | **mature** |
| bizlogic | 1 | 10 | 10 | 15 (+10) | 6 | 2 | **mature** |

All 4 classes went `researching` → `mature`, `missing=[]`. Total 29 new items, all
`high_confidence`. Nothing was held or rejected in the final state of any file.

## 2. Anti-fabrication control actually exercised

A harness (`qcheck.py`, scratch) checked every candidate quote against the **live
page** using the pipeline's own `pipeline.fetch` and the gate's own
`verify_quotes.find_quote` **before** writing any intake file. 79 candidates
checked across 4 batches; **6 failed** and none of the 6 was stored:

| failed quote | cause | action |
|---|---|---|
| NVD CVE-2019-0708 description | page is a **client-rendered stub** (1618 chars) — description absent | rdp NVD source **dropped entirely** |
| OWASP CSRF cheat sheet, CORS/no-JavaScript line | not present in the current revision | item rewritten without it |
| CWE-352, `this weakness is a Composite - ...` | I had prefixed text not on the page | replaced with the verbatim span |
| portswigger examples, "This enables them to create email addresses..." | drafted from paraphrase | quote **deleted**, item kept with verified quotes |
| learn.microsoft "Group Policy is a feature" | not on the page | **dropped** |
| cwe.mitre "Group Policy scope"/"Loopback Processing" | 404 / absent | **dropped** |

Two further "failures" were my own placeholder probe strings (`cwe522 creds`,
`ts examples`) and were never evidence.

The gate also independently caught things my harness had already cleared, which is
the control working: 3 bizlogic items and 2 rdp items were **held
`INSUFFICIENT_PUBLISHER_HOSTS`** on first dry run because their sources collapsed
to one publisher org. Two traps worth naming, because a naive count of hosts
misses both:

- `wstg.owasp.org` and `cheatsheetseries.owasp.org` are **one** publisher
  (`owasp.org`) — pairing them does not corroborate.
- A WebSocket-CSRF item citing two `portswigger.net` pages is **one** publisher.

Both were fixed by adding a genuinely independent org (portswigger↔owasp↔mitre↔w3),
never by adding a second page from the same host.

A `cwe.mitre.org` CWE-327 quote was **deliberately discarded** for the encryption-oracle
item: CWE-327 is about *broken* algorithms, not oracle reuse, and citing it would
have been a live-but-wrong reference — the exact defect the brief warns about. CWE-840
was used instead.

## 3. Moved pages (404 ≠ fabrication)

`wstg.owasp.org/.../04-Business_Logic_Testing/` 404s. The section moved to
`10-Business_Logic_Testing/`. Located by reading the live nav index, and all WSTG
citations use the **live** path. Verified on 11 WSTG pages at 200 with real prose
under the nav chrome.

## 4. Final measured output (quoted, not estimated)

`python -m wks.cli gaps`

```
class                    state         pri items  sup  fp chn  missing
ad_group_policy          mature          0    13   13   2   1
bizlogic                 mature          0    15   15   6   2
csrf                     mature          0    16   16   4   1
rdp                      mature          0    15   15   3   1
```

`python -m wks.cli metrics`

```
items_total: 500
items_by_state: {'high_confidence': 484, 'under_review': 16}
promotion_rate_pct: 96.8        disproof_rate_pct: 100.0
sources: 473                    classes: 62
classes_mature: 12              class_maturity_pct: 19.35
false_positive_rules: 197  (fp_case 70 / fp_rule_items 127)
chains: 32                      chain_link_segments: 48
open_conflicts: 10
```

Corpus-wide before → after: items **472 → 500** active (501 rows incl. 1
pre-existing superseded idor row, which `metrics` correctly excludes);
sources 464 → 473; chains 28 → 32; chain_steps 111 → 120;
classes_mature 8 → 12 (12.9% → 19.35%). The 16 `under_review` rows are
**pre-existing** and untouched — this wave added 0 held items.

`python -m wks.cli domain-health`

```
  web        declared=15   registered=15   items=219
  network    declared=25   registered=25   items=148
```

`python -m wks.verify_quotes --class <c>` — **every quote re-verified against the
live page**, re-run after the taxonomy render:

```
rdp VERIFIED=15   ad_group_policy VERIFIED=13   csrf VERIFIED=16   bizlogic VERIFIED=15
```

`python -m wks.cli selftest` → `ALL WKS GATE TESTS PASS` (includes the
fingerprinted-file self-audit, so no threshold file was modified).
`taxonomy_write.py --check` → `OK — 140 files match the spec and the canonical db`
(4 pages were stale after ingest; regenerated from gated rows, then re-checked).
`audit_taxonomy.py` → `OK — one canonical home per class, no dead pointers`.

## 5. Files created (intake only; nothing else modified)

- `research/incoming/gapfill-csrf.json` (10 items)
- `research/incoming/gapfill-csrf-chain.json` (1 item + chain)
- `research/incoming/gapfill-bizlogic.json` (10 items, incl. 1 chain)
- `research/incoming/gapfill-rdp.json` (5 items)
- `research/incoming/gapfill-rdp-chain.json` (1 item + chain)
- `research/incoming/gapfill-ad_group_policy.json` (2 items, incl. 1 chain)
- `db/wks.db.bak-20261002-150914` (snapshot; row counts verified on the copy)
- regenerated `bug-classes/**` pages for the 4 classes (4 files changed by the
  standard generator, not hand-edited)

Restore: `cp db/wks.db.bak-20261002-150914 db/wks.db`

## 6. Honest limitations

- New publishers used: `portswigger.net`, `cheatsheetseries.owasp.org`,
  `wstg.owasp.org`, `cwe.mitre.org`, `attack.mitre.org`, `learn.microsoft.com`,
  `www.w3.org`. New distinct hosts added: **1** (w3.org); the rest were already in
  the registry, so per-host diversity barely moved even though 29 items landed.
- `open_conflicts: 10` is unchanged and unexamined — no attempt was made to close
  them, and none of the new items was checked against them.
- The new items are documentation-derived. No lab or target was touched; nothing
  here is exploitation evidence.
