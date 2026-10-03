# HackTricks harvest — what happened, measured

Goal and criteria: `research/ht_goal.md`. Gap analysis: `research/ht_gap_analysis.md`.

## Result

| | before | after |
|---|---|---|
| items_total | 1556 | 1631 |
| active items | — | 1507 |
| high_confidence | 914 | 985 |
| classes with a `class_domain` row | 40/62 | **62/62** |
| HackTricks-citing promoted items | 0 | **74** |

Every number re-derived from the db, not read off an ingest summary.

## Pipeline

```
SUMMARY.md (1066 pages)  ->  ht_xwalk4.py   crosswalk: 285 matched / 378 gap / 403 out-of-scope
class pages (9)          ->  ht_make_packets.py   REAL quotes sliced out of the cached pages
packets                  ->  ht_brief.py    a flat brief per child
children (2 waves)      ->  claims authored by children (80 candidates)
                         ->  ht_audit_claims.py   parent re-audits D1-D4, 74 pass
                         ->  ht_stage.py   re-verifies each quote, builds intake files
intake files             ->  wks.ingest     72 promoted, 0 rejected, 0 fabricated
                         ->  ht_live_verify.py   re-fetch from the INTERNET: 144/144
```

## Six defects found and fixed (each was measured, not assumed)

1. **`stem_key` split filenames on `-` and kept the first token**, so
   `file-integrity-monitoring.md` scored an exact 99.0 against class
   `file_upload` (stem "file") and dragged 57 unrelated pages in. Fixed: a
   stem is the whole normalised name; the first token is a weak hint only.

2. **Purely lexical scoring misrouted four paths a human would not** — DNS →
   `subdomain_takeover`, the AD methodology root → `password_attacks`,
   `adws-enumeration` → `internal_recon`, and HackTricks merges
   `cache_deception` + `cache_poisoning` in ONE directory while our taxonomy
   splits them. Fixed with a hand-verified `ANCHOR` table and split rules.

3. **One generic token routed a whole subtree**: `file_upload` lists the alias
   `"web shell upload"`, so the token "web" captured 51 pages under
   `network-services-pentesting/pentesting-web/`. Fixed with IDF weighting over
   the class vocabulary plus a runner-up margin test. `file_upload` went
   71 pages → 3, and the 51 false entries went to 0.

4. **v3's tie-breaking was row-order dependent** — `score()` used a strict `>`
   over unordered sqlite rows, so equal scores resolved differently between
   runs. Fixed by sorting the ranking; v4 is byte-identical across runs and
   independent of `$PWD`.

5. **`class_domain.specialization` is `NOT NULL DEFAULT ''`** and I passed
   explicit `NULL`, so `INSERT OR IGNORE` swallowed the violation and reported
   success with **zero rows written**. Caught by asserting the count
   afterwards, not by trusting `rowcount`. Now 62/62 with an assert.

6. **A malformed partner quote shipped into 3 promoted items.** The OWASP
   XSS cheat sheet's JSON advice spliced to the heading
   `Output Encoding for "CSS Contexts" ¶` and on into the CSS paragraph.
   Every fragment is verbatim, so it looked real — but the joined form does not
   re-verify against the live page, which is the test that matters. Caught only
   by live re-fetch, not by the cache. Fixed in `sentences()` (never cross a
   heading) and at **recycle time** in `ht_stage.py`; the 3 rows were
   superseded per invariant I8.

## Three traps specific to HackTricks

- **`book.hacktricks.wiki` serves a byte-identical 48195-byte body** for
  `idor/` and `sqli/` — a catch-all shell. A 200 proves nothing.
- **`hacktricks.wiki/en/<path>.html` returns a 650-byte "Page not found"** for
  some paths (`sqli.html`) and real content for others (`idor.html`).
- **Only `raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/…md`
  is safe**: the file itself, distinct per path, and it is what the gate fetches.
  The blob URL is 281KB of viewer markup that does not contain the quote.

## The self-corroboration trap (why HackTricks alone can never promote)

HackTricks is available at `hacktricks.wiki` AND
`raw.githubusercontent.com/HackTricks-wiki`. `publisher_org()` counts those as
**two** orgs, so an item citing the same document on both hosts satisfies
`MIN_PUBLISHER_HOSTS = 2` **on one editorial voice**. `ht_verify.py` and
`ht_live_verify.py` both collapse the HackTricks property and report
`self_corroborating`; the harvest measured **0**.

The partner quote is therefore *recycled* from an item in our own corpus that
already promoted on that publisher — so it is known to exist verbatim and to
have passed the gate. Nothing in the partner path is typed.

## Two gate findings worth keeping

- **The topic gate cannot detect a padded claim.** `relevance.assess()` returns
  `ON_TOPIC` on any own-vocabulary hit, by design, to protect genuine knowledge.
  A template that pastes the class name in is therefore *guaranteed* to pass. The
  first plan generator produced `"wifi tools reference is the practical test for
  idor"` and the gate approved it. Fixed by architecture: the tool emits
  **evidence**, never a claim, and a child authors claims from a real quote.
- **`item_key LIKE '%.ht_%'` is a bad filter.** `_` is a single-character
  wildcard in SQL LIKE, so `.ht_` also matches `.htm` and the diagnostic
  returned 4 pre-existing items that had nothing to do with this harvest.
  Use `GLOB '*.ht_*'` or `LIKE ... ESCAPE`.

## One stale-data trap

`store.add_item()` returns the existing id when an `item_key` exists and never
updates the claim. So re-ingesting a *revised* claim is silently a no-op: the
old text survives and the revision is lost. Caught by reading the stored claim
back after the second ingest. A revised claim needs a new key, with
`wks.reconcile` superseding the old row.

## What a promoted item is worth here

The claims that survived review are genuinely usable, e.g.

- `[idor/prerequisite]` IDOR is only validated with two identities the tester
  controls, because a serial number seen on the device is not proof of
  ownership.
- `[xss/signal]` Reflection alone is not a cross-site scripting finding when the
  reflected payload sits in the body of a 302 — the browser never renders it.
- `[xss/signal]` The sink to hunt in extension code is input → HTML string →
  DOM append, because that route stays open where the extension CSP blocks
  eval-like and inline execution.

## Verified at the end

| check | result |
|---|---|
| packet quotes (cached, own page) | 80/80, 0 mismatch, 0 furniture, 0 self-corroborating |
| promoted items re-fetched LIVE | 72 items, **144/144 quotes verify**, 0 dead |
| ingest | 72 submitted, 72 promoted, **0 rejected**, 0 shape errors |
| `wks.cli selftest` | ALL WKS GATE TESTS PASS |
| `orch.cli gate` | OK, 6 files fingerprinted, MIN_PUBLISHER_HOSTS still 2 |
| `taxonomy_write.py --check` | 142 files match the canonical db |
| `wks.domains --check` | 0 problems across 62 classes |
| retrieval | the new items are returned by `wks.cli search` with their evidence |

## Not done

- **48 HackTricks privesc pages are unmapped and there is no privesc class at
  all** (see `ht_gap_analysis.md` §3). That is the next subgoal: register 5
  classes, not 14, and harvest them.
- The macOS privesc section (84 pages) is out of scope as you specified.
- No `chains` or `fp_case` rows were authored — HackTricks prose does not carry
  FP guidance, and the existing tools own that.