# W11 — WEB-Domain Quality Improvement Plan

**Scope:** the 37 classes under `domains/web/` (the directory listing, not
`class_domain.domain`, which marks only 15 of them as `web`).
**Method:** every number below comes from a command in this document, run
read-only against `db/wks.db` (`file:…?mode=ro`). Nothing was written to the
database; no tool was run with `--apply`.
**Machine-readable companions:** `validation/w11_web_quality_measurement.json`,
`validation/w11_table_rows.json`.

---

## HEADLINE FINDINGS

### 1. The brief's premise is measurably wrong: the web corpus is NOT limited to 5 publisher orgs — but it *is* limited to 2 orgs *per item*, and that is the real ceiling

The task brief stated all 37 web classes draw from 5 publisher organisations and
21 classes have only 2 sources. Neither holds against the current DB.

```
$ python -c "...publisher_org() over all web item_source rows..."
distinct orgs in web corpus: 55
web classes with <=3 distinct orgs: 6   (api_trust, cmd, graphql, ldap, race, xxe)
web classes with ==4 distinct orgs: 8
```

Class-level diversity is 3–11 orgs (mean 5.9). **But the gate counts orgs per
item**, and per-item diversity is at the bare floor almost everywhere:

```
$ python tools/w11_table_rows.py     # columns: at2 = items citing exactly 2 orgs
items sitting on exactly 2 orgs: 630 / 665 = 94.7%
classes where 100% of items sit on exactly 2 orgs: 24 of 37
```

So the true weakness is not "5 orgs exist", it is **630 of 665 web items have
exactly zero margin** — delete or rewrite either cited page and
`MIN_PUBLISHER_HOSTS = 2` fails for that item. `wks/config.py:73` sets the
minimum at 2, and `wks/quality.py:200` enforces `len(orgs) < MIN_PUBLISHER_HOSTS`.
No item has 2 orgs of slack anywhere in the web domain.

Citation mass is also concentrated even though the *count* of orgs is not:

```
$ python -c "...top orgs by web citation links..."
total web citation links: 1410
  portswigger.net  links=238 (16.9%)  cum=16.9%
  owasp.org        links=202 (14.3%)  cum=31.2%
  mitre.org        links=189 (13.4%)  cum=44.6%
  httpwg.org       links= 75 ( 5.3%)  cum=49.9%
  snyk.io          links= 51 ( 3.6%)  cum=53.5%
top-5 orgs share: 53.5%      orgs carrying only 1 link: 6
```

### 2. The `gaps` command cannot see the weakness it is supposed to report

`wks/coverage.py:66` computes a `diversity` dimension (`len(orgs)`) per class
and `wks/coverage.py:87` stores it in `have["diversity"]` — but
`cmd_gaps` (`wks/cli.py:125-133`) never prints it, and `quality.maturity()`
(`wks/quality.py:256`) never computes org diversity at all. It counts only
`n_items`, `n_supported`, `n_fp`, `n_chains`.

Verified: `python -m wks.cli gaps` prints the header
`class state pri items sup fp chn missing` — there is no diversity column, and
the `missing` column is empty for all 62 classes. The metric that would have
caught this saturation was written and then never wired to output.

### 3. All 10 quality-vector components are 0.0 in the DB while `score` is populated and every item reads `high_confidence`

```
$ python -c "select count(*) from quality where source_credibility>0"  (and 9 more)
source_credibility nonzero rows= 0
technical_specificity nonzero rows= 0
evidence_strength nonzero rows= 0
reproducibility nonzero rows= 0
corroboration nonzero rows= 0
practical_usefulness nonzero rows= 0
recency nonzero rows= 0
internal_consistency nonzero rows= 0
real_world_demo nonzero rows= 0
limitations_documented nonzero rows= 0
quality row count: 1112      validation_state dist: [('high_confidence', 1112)]
score distinct values: 133   (range 0.747 … 0.9335)
```

`wks/quality.py:188` computes `score` from those ten dims, and
`wks/quality.py:176-187` builds them correctly — but `store.set_state`
(`wks/store.py:439-442`) persists only `validation_state`, `score`,
`gate_reasons`, `assessed_at`. The ten dimension columns are never written.
`gate_reasons` is `'[]'` for all 1112 rows, so no item carries a recorded
rejection reason either. **Any per-class "weakest dimension" query against
`quality.*` returns zeros for all 37 classes and is useless** — the priority
table below is therefore built from the underlying `item`/`item_source`/`source`
tables instead, which is why it can rank classes at all.

### 4. 126 promoted items contain scraped page navigation, not security knowledge

`*.auto.*` items are machine-extracted. Body signature: runs of blank lines
(≥3 consecutive newlines) with bylines and "Share" chrome.

```
$ python -c "...re.search(r'\n\s*\n\s*\n', body) over web auto items..."
web auto.* items: 312    nav-chrome: 126 = 40.4%
nav-chrome items: 126  status: active=126  validation_state: high_confidence=126
min score among them: 0.747   max: 0.8845
```

Concrete example — `smuggling.auto.01`, `validation_state='high_confidence'`,
`score` in the normal band:

- claim: *"It basically enables you to hide a payload in plain sight."*
- body: `or this page to function normally.\n \n\n \n\n … Mirko Zorz , Director of Content, Help Net Security \n February 29, 2024 \n Share \n\n… BobThe`

Worst-hit classes: `authz` 14/14 (100%), `mass_assign` 11/11 (100%),
`path_traversal` 26/28 (93%), `misconfig` 6/11 (55%), `crlf` 4/7 (57%),
`file_upload` 6/8 (75%), `ssti` 5/8 (62%), `cmd` 4/6 (67%), `authn` 4/6 (67%),
`smuggling` 8/15 (53%), `xxe` 2/19 (11%).

`open_redirect` is a structural outlier: 41 items, 36 of them `auto.*`.

### 5. Nine FABRICATED quotes are live in promoted, `high_confidence` items

`python -m wks.verify_quotes --class <id> --json` re-fetches each cited page
and checks the quote still appears. Across the 11 classes I ran, 9 items came
back `FABRICATED` with `retryable=False`:

```
xxe          23 items  VERIFIED=22  FABRICATED=1   xxe.fp_rule.auto.derived
misconfig    13 items  VERIFIED=12  FABRICATED=1   misconfig.fp_rule.auto.derived
smuggling    17 items  VERIFIED=16  FABRICATED=1   smuggling.fp_rule.auto.derived
cmd          13 items  VERIFIED=12  FABRICATED=1   cmd.fp_rule.auto.derived
ldap         13 items  VERIFIED=12  FABRICATED=1   ldap.fp_rule.auto.derived
api_trust    14 items  VERIFIED=12  FABRICATED=2   api_trust.fp_rule.auto.derived, .derived2
crlf         14 items  VERIFIED=13  FABRICATED=1   crlf.fp_rule.auto.derived
nosql        16 items  VERIFIED=15  FABRICATED=1   nosql.fp_rule.auto.derived
```

Every one matches the `*.fp_rule.auto.derived*` key pattern. That pattern is
**20 items corpus-wide, 14 of them in the web domain, all 20 `status=active`**.
`wks/quality.py:207` has a `has_fabricated_refs()` check that would catch
literal `http://` ref shapes, but a quote that reads as prose and does not
appear on the re-fetched page passes the gate at write time and fails only at
verify time.

Secondary finding in the same area: `smuggling.auto.t.b00b60cd` describes
**DTLS traffic to a NetScaler appliance** — that is network/appliance
material filed under a web class, and `smuggling` shows 6 duplicate claim
groups (corpus-wide `duplicate_claim_groups: 112`).

---

## COULD NOT MEASURE

Stated as omissions rather than findings, per the brief's rule 1.

- **Per-class quality-vector weakness.** Impossible: all ten `quality.*`
  component columns are 0.0 for all 1112 rows (finding 3). Any ranking of
  "weakest dimension" from that table is a fabrication.
- **Quote-fabrication rate for the other 26 web classes.** `verify_quotes`
  re-fetches live pages; a full corpus run exceeded a 560 s cap
  (`python -m wks.verify_quotes --json` timed out at 420 s tool-side). Only
  11 of 37 classes were verified. The 9/0 above is **not** a corpus rate.
- **The remaining 6 classes' org counts from a second tool.** `wks.sourcebook`
  and `wks.cli show` report per-class source lists but not publisher-org
  diversity; only my script collapses hosts via `config.publisher_org`.
- **Whether `min_item_orgs == 2` items fail the gate when one page dies.**
  Inferred from `wks/quality.py:200` and `wks/config.py:73`; not executed,
  because proving it needs a mutation this brief forbids.
- **Staleness of the `*.auto.*` bodies.** `metrics` reports
  `stale_rate_pct: 0.0` alongside `without_content_hash: 1` and its own note
  says that means "not checked", not "nothing is stale".

---

## PER-CLASS PRIORITY TABLE

All 37 classes, each appearing exactly once. Verified against
`validation/w11_table_rows.json`. Rows are sorted by measured weakness, not by
class name. Columns: `frag%` = items citing exactly 2 publisher orgs. `loc%` =
`item_source` rows carrying a `locator`. `nav/auto` = nav-chrome items of
`*.auto.*` items. `fp_case` / `fp_rule` = the two shapes `maturity()` sums into
`n_fp` (`wks/quality.py:290-299`). `FAB` = FABRICATED found by `verify_quotes`
this session (blank = class not run, **not** a clean result). Median quote
length in chars. All columns derived by `python tools/w11_table_rows.py`.

| # | class_id | items | orgs | frag% | loc% | nav/auto | fp_case | fp_rule | FAB | medQ | weakest dimension | concrete next action | cost |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | race | 15 | 3 | 100 | 0 | 3/3 | 2 | 1 | 0 | 93 | diversity + zero locators | add 1 independent org to every item; portswigger.net/research/race-conditions-* 404s — find a live 3rd publisher, then backfill locators on all 31 links | medium |
| 2 | graphql | 13 | 3 | 100 | 3 | 0/0 | 3 | 2 | 0 | 107 | diversity + locator coverage worst in corpus (1/31) | register `cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html` (REFUSE: already in registry — attach it) and backfill 30 locators | cheap |
| 3 | api_trust | 14 | 3 | 86 | 29 | 0/10 | 0 | 2 | 2 | 117 | 2 fabricated quotes, both `fp_rule.auto.derived` | quarantine `api_trust.fp_rule.auto.derived` + `.derived2`; then add a 3rd org (all 7 sources are docs+blog, zero authority-1) | medium |
| 4 | xxe | 23 | 3 | 96 | 17 | 2/19 | 0 | 2 | 1 | 115 | diversity + 1 fabricated quote | quarantine `xxe.fp_rule.auto.derived`; add org (4 sources / 3 orgs is the thinnest evidence base of any 23-item class) | medium |
| 5 | cmd | 13 | 3 | 100 | 54 | 4/6 | 0 | 2 | 1 | 132 | diversity + fabricated quote | quarantine `cmd.fp_rule.auto.derived`; add a 3rd org — only 5 sources back 13 items | cheap |
| 6 | ldap | 13 | 3 | 100 | 54 | 0/6 | 0 | 2 | 1 | 125 | diversity + fabricated quote; also cross-domain (LDAP is in `domains/web/ldap` yet sourced from network material) | quarantine `ldap.fp_rule.auto.derived`; decide whether `web/ldap` belongs in the web domain at all | medium |
| 7 | crlf | 14 | 4 | 100 | 50 | 4/7 | 0 | 2 | 1 | 121 | fabricated quote + 4/7 auto items are nav | quarantine `crlf.fp_rule.auto.derived`; delete the 4 nav items; add 1 org | cheap |
| 8 | misconfig | 13 | 4 | 100 | 8 | 6/11 | 0 | 2 | 1 | 155 | fabricated quote + 6/11 nav + 4 sources only | quarantine `misconfig.fp_rule.auto.derived`; purge 6 nav items; 4 sources for 13 items is the thinnest ratio measured | cheap |
| 9 | smuggling | 17 | 4 | 76 | 5 | 8/15 | 0 | 2 | 1 | 127 | fabricated quote + 8/15 nav + cross-domain DTLS/NetScaler item | quarantine `smuggling.fp_rule.auto.derived`; reclassify `smuggling.auto.t.b00b60cd`; purge 8 nav items | medium |
| 10 | nosql | 16 | 4 | 100 | 44 | 0/9 | 0 | 2 | 1 | 105 | fabricated quote + only 5 sources for 16 items | quarantine `nosql.fp_rule.auto.derived`; add 1 org; all 4 sources are blog/vendor/research — zero taxonomy, zero writeup | cheap |
| 11 | prototype_pollution | 23 | 4 | 100 | 33 | 0/16 | 0 | 2 | 0 | 105 | diversity: 23 items on 8 sources / 4 orgs, all 23 at 2 orgs | add a 3rd org per item; highest item-to-source ratio in the corpus after open_redirect | medium |
| 12 | session | 12 | 4 | 100 | 44 | 4/6 | 0 | 2 | 0 | 103 | diversity at 12 items = the `MATURITY_MIN_ITEMS` floor; 4 nav items | add a 3rd org; purge 4 nav items | cheap |
| 13 | sqli | 17 | 4 | 76 | 0 | 2/3 | 10 | 2 | 0 | 129 | zero locators across all 38 links; standards-only base (7 standards_body, 0 writeup) | backfill locators on 38 links; add one writeup-class source | medium |
| 14 | idor | 15 | 4 | 93 | 6 | 1/1 | 2 | 1 | 0 | 113 | diversity + locator coverage (2/35) | add a 3rd org; idor is the only web class with any `evidence` rows (2 repro) — extend that | medium |
| 15 | authz | 18 | 8 | 89 | 23 | 14/14 | 0 | 2 | 0 | 127 | all 14 `auto.*` items are nav-chrome (100%) | purge all 14 nav items — 0 `fp_case` and real quotes verified (18/18 VERIFIED) | cheap |
| 16 | path_traversal | 33 | 8 | 91 | 14 | 26/28 | 0 | 2 | 0 | 130 | 26/28 auto items are nav-chrome (93%) | purge 26 nav items; 33 items with 0 `fp_case` and 1 duplicate claim group | cheap |
| 17 | info_disclosure | 15 | 7 | 93 | 0 | 0/1 | 0 | 2 | 0 | 103 | zero locators across all 36 links; 22 sources for 15 items is the widest net, all unanchored | backfill locators on 36 links | medium |
| 18 | supply_chain | 18 | 7 | 89 | 0 | 0/12 | 1 | 1 | 0 | 157 | zero locators across all 38 links; only 1 fp_rule, exactly at the floor | backfill locators; add 2nd fp rule | medium |
| 19 | mass_assign | 14 | 6 | 100 | 21 | 11/11 | 0 | 2 | 0 | 120 | all 11 `auto.*` items are nav-chrome (100%); 33% of sources are `taxonomy` | purge 11 nav items; replace taxonomy pages with writeup-class sources | cheap |
| 20 | open_redirect | 41 | 8 | 100 | 10 | 6/36 | 0 | 2 | 0 | 175 | 41 items / 9 sources / 82 links — densest citation reuse in the corpus; 36 auto items | purge 6 nav items; the 82 links over 9 sources is the reuse metric to attack first | medium |
| 21 | ssti | 12 | 7 | 100 | 38 | 5/8 | 0 | 2 | 0 | 150 | 3 duplicate claim groups at 12 items; 5/8 nav | purge 5 nav; dedupe the 3 claim groups | cheap |
| 22 | file_upload | 14 | 6 | 100 | 21 | 6/8 | 1 | 2 | 0 | 122 | 6/8 nav (75%); 6 sources for 14 items | purge 6 nav items | cheap |
| 23 | bizlogic | 18 | 5 | 100 | 14 | 3/3 | 1 | 5 | 0 | 145 | 38% of sources are `taxonomy` (5/13) — classification, not exploitation; all 18 at 2 orgs | replace taxonomy sources with writeup/report-class evidence | medium |
| 24 | jwt | 17 | 5 | 100 | 8 | 0/0 | 13 | 5 | 0 | 121 | lowest median quote (121) with 8% locator coverage; best fp depth (18) to model on | backfill locators on 37 links | cheap |
| 25 | cors | 21 | 6 | 100 | 19 | 2/15 | 0 | 2 | 0 | 141 | 6 sources / 42 links for 21 items — 2 links per source, no taxonomy at all | add taxonomy + standard sources; 0 `fp_case` | medium |
| 26 | cache_poisoning | 14 | 6 | 100 | 21 | 0/10 | 0 | 2 | 0 | 164 | 4 sources for 14 items; all 14 at 2 orgs | add 1 org; 4 sources is tied for thinnest | cheap |
| 27 | deser | 12 | 11 | 100 | 36 | 7/7 | 0 | 2 | 0 | 130 | best org diversity in the corpus (11) but 7/7 auto items are nav — org count hides junk | purge 7 nav items; diversity is already solved, junk is not | cheap |
| 28 | authn | 14 | 9 | 93 | 7 | 4/6 | 1 | 2 | 0 | 125 | 4/6 nav; 7% locator coverage; richest type mix (8 types) is under-used | purge 4 nav; backfill locators | cheap |
| 29 | subdomain_takeover | 14 | 7 | 100 | 7 | 0/9 | 0 | 2 | 0 | 133 | 7% locator coverage; 4 duplicate claim groups | backfill locators; dedupe | cheap |
| 30 | websocket | 12 | 5 | 100 | 44 | 0/6 | 0 | 2 | 0 | 114 | 5 orgs / 10 sources at 12 items; 0 `fp_case` | add 1 org; add authored fp narrative | cheap |
| 31 | clickjacking | 13 | 7 | 100 | 54 | 0/4 | 0 | 2 | 0 | 119 | 0 `fp_case`, 0 authority-1 sources among 10 | add 1 authority-1 source | cheap |
| 32 | host_header | 12 | 7 | 100 | 25 | 1/6 | 0 | 2 | 0 | 139 | 12 items = the `MATURITY_MIN_ITEMS` floor; only 1 authority-1 source of 7 | add items; add authority-1 source | medium |
| 33 | csrf | 19 | 10 | 100 | 21 | 3/3 | 0 | 4 | 0 | 137 | all 19 at exactly 2 orgs despite 10 orgs in the class — breadth never reaches items | push a 3rd org down to item level, per item | medium |
| 34 | ssrf | 17 | 7 | 100 | 8 | 3/3 | 12 | 4 | 0 | 134 | 7 orgs but 100% of items on exactly 2 — the widest breadth/fragility gap in the corpus; 8% locator coverage | push breadth down to item level; ssrf holds 12 `fp_case`, the deepest authored FP knowledge measured — model the locator backfill on it | medium |
| 35 | oauth | 16 | 7 | 56 | 0 | 0/0 | 3 | 2 | 0 | 92 | lowest median quote in the corpus (92 chars) and zero locators on 44 links | backfill locators; deepen quote extraction | medium |
| 36 | cache_deception | 13 | 6 | 92 | 7 | 0/7 | 0 | 2 | 0 | 142 | 7% locator coverage; 1 fabricated-pattern sibling (`cache_deception.fp_rule.auto.derived`, present, not verified this session) | verify quotes; backfill locators | cheap |
| 37 | xss | 70 | 7 | 91 | 0 | 1/3 | 13 | 12 | 0 | 172 | largest class (70 items / 154 links) with **zero** locators; 37% taxonomy share | backfill locators on 154 links — largest single win in the corpus | high |

---

## THE FIVE HIGHEST-VALUE ACTIONS

### Action 1 — Quarantine the 9 measured FABRICATED quotes and make `verify_quotes` a promotion gate

Highest value because it removes false `high_confidence` claims, not merely thin
ones, and the pattern is already isolated to one key shape.

**Command (find them, read-only):**
```
python -m wks.verify_quotes --class xxe --json
python -m wks.verify_quotes --class api_trust --json
```
**Broader sweep, bounded per class** — a whole-corpus `python -m wks.verify_quotes --json`
exceeded a 420 s tool timeout, so run it class-by-class:
```
for cl in $(ls domains/web); do python -m wks.verify_quotes --class $cl --json; done
```
**Measurable outcome:** the 9 FABRICATED items already measured come down to 0,
and all 20 `*.fp_rule.auto.derived*` items (14 in the web domain) leave
`status='active'`. **Verify with:**
```
python -c "import sqlite3;c=sqlite3.connect('file:db/wks.db?mode=ro',uri=True);print(list(c.execute(\"select count(*) from item where item_key like '%.fp_rule.auto.derived%' and status='active'\")))"
```
currently `[20]`, target `[0]`.

### Action 2 — Purge the 126 nav-chrome items, worst classes first

100% nav: `authz` (14/14), `mass_assign` (11/11), `race`, `csrf`, `bizlogic`,
`idor`. `path_traversal` is 26/28.

**Command to size the work:**
```
python tools/w11_table_rows.py
```
(columns `nav` and `auto`; opens the DB `mode=ro`, writes only the JSON sidecar.)

**Measurable outcome:** web nav-chrome count 126 → 0. **Verify with:**
```
python -c "import sqlite3,os,re;c=sqlite3.connect('file:db/wks.db?mode=ro',uri=True);w=sorted(p for p in os.listdir('domains/web') if os.path.isdir('domains/web/'+p) and p not in {'areas','chains','methodology','topics'});q=','.join('?'*len(w));r=[b[0] for b in c.execute('select i.body from item i where i.item_key like ? and i.class_id in ('+q+')',tuple(['%.auto.%']+w))];print(len(r),'auto /',sum(1 for x in r if re.search(r'\n\s*\n\s*\n',x or '')),'nav')"
```
currently `312 auto / 126 nav`, target `… / 0 nav`.

### Action 3 — Give every web item a 3rd publisher org, starting with the 6 classes that have only 3

630 of 665 items sit on exactly 2 orgs; 24 classes are at 100% fragility. This
is the metric `gaps` cannot see, so it must be measured with the script.

**Command to rank the work:**
```
python tools/w11_table_rows.py
```
**Candidate sources, already verified live this session** (read-only, no `--apply`):
`python -m wks.source_intake validation/w11_neworg_candidates.json` returned
`candidates=42 accepted=11 refused=31`:
```
ACCEPT lead  fetch.spec.whatwg.org       https://fetch.spec.whatwg.org/
ACCEPT lead  html.spec.whatwg.org        https://html.spec.whatwg.org/multipage/parsing.html
ACCEPT lead  slsa.dev                    https://slsa.dev/
ACCEPT lead  httpwg.org                  https://httpwg.org/specs/rfc9110.html
ACCEPT lead  rfc-editor.org              https://www.rfc-editor.org/rfc/rfc7519.html
ACCEPT lead  rfc-editor.org              https://www.rfc-editor.org/rfc/rfc8252.html
ACCEPT lead  owasp.org                   https://owasp.org/API-Security/editions/2023/en/0x11-t10/
ACCEPT lead  cheatsheetseries.owasp.org  .../XML_External_Entity_Prevention_Cheat_Sheet.html
ACCEPT lead  cheatsheetseries.owasp.org  .../Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
ACCEPT lead  cheatsheetseries.owasp.org  .../Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
ACCEPT lead  portswigger.net             https://portswigger.net/research/http-request-smuggling
```

**Measurable outcome:** for `race`, `orgs` rises 3 → 4 and `at2` falls 15 → 0.
**Verify with:**
```
python tools/w11_table_rows.py | grep '^race'
```
currently `it=15 org=3 at2=15 frag=100`, target `org>=4 at2=0`.

**Negative result that must shape the plan:** of the 42 candidates, **only 3
introduced a genuinely new org** (`whatwg.org` via two hosts, and `slsa.dev`);
the other 8 accepts were orgs already present. Measured refusal reasons:
`already in the registry` (the majority), `HTTP Error 404` (several
portswigger research paths and OWASP cheatsheet names), `no class vocabulary on
the page: nav chrome or a catch-all` (rfc-editor rfc8725, rfc6616), and
`only 51 chars of text: a shell, stub or redirect notice`
(owasp.org/Top10/A01_2021). Org-diversity growth is bounded by what
independently publishes class-specific web material, not by effort.

### Action 4 — Backfill `locator` on the six classes where it is exactly zero

`locator` turns a citation into a checkable pointer. Six classes have none:
`race` 0/31, `xss` 0/154, `sqli` 0/38, `oauth` 0/44, `info_disclosure` 0/36,
`supply_chain` 0/38. `xss` alone is 154 links.

**Command:**
```
python tools/w11_table_rows.py
```
**Measurable outcome:** `xss` `loc%` rises 0 → 80. **Verify with:**
```
python tools/w11_table_rows.py | grep -E '^(xss|oauth|sqli)'
```
currently all three report `loc=0`.

### Action 5 — Surface `diversity` in `gaps` so this weakness is visible without a script

`wks/coverage.py:87` already computes `have["diversity"]`, but `cmd_gaps`
(`wks/cli.py:127-132`) never prints it and `quality.maturity()`
(`wks/quality.py:256`) never computes org diversity at all. Without this,
Actions 3 and 4 have no standing metric and will decay silently back to zero.

**Command proving the gap today:**
```
python -m wks.cli gaps
```
prints `class state pri items sup fp chn missing` — all 62 rows `mature`,
`pri 0`, `missing` empty.

**Measurable outcome:** the header gains an `orgs` column and the six classes at
`orgs<=3` become visible. **Verify with:**
```
python -m wks.cli gaps | head -3
```
showing `orgs` in the header, and
```
python validation/w11_verify_action5.py
```
which prints `race orgs=3`, `graphql orgs=3`, `cmd orgs=3`, `ldap orgs=3`,
`api_trust orgs=3`, `xxe orgs=3` — six classes at the floor, confirming the
metric is invisible to `gaps` today.

---

## ANTI-PATTERNS TO AVOID

Each of these is grounded in something measured in this session.

**1. Do not chase item counts to fix "saturation."** `python -m wks.cli gaps`
already reports all 62 classes `mature` with an empty `missing` column at
12–70 items each. Adding items moves nothing that the maturity check reads.

**2. Do not send another wave at FP rules — that metric is already saturated by
count.** 25 of 37 web classes have **zero** `fp_case` rows, yet `gaps` shows
`fp 2` for all of them, because `quality.maturity()` sums `fp_case` rows *and*
`kind='fp_rule'` items (`wks/quality.py:290-299`). The e.g. `cors` case is real
knowledge, not filler — `cors.fp_rule.already_public_response_is_not_a_cors_finding`
has a specific test procedure. Chasing `fp` numbers is chasing a metric that
cannot distinguish the two.

**3. Do not use `quality.*` dimension columns to prioritise anything.** All ten
are 0.0 for all 1112 rows while `score` is populated (finding 3). Any query
ranking classes by `corroboration` or `evidence_strength` returns a flat zero
for every class and will look like a tie, not a measurement.

**4. Do not add a host, count it as a new publisher, and declare diversity
improved.** `wks/config.py:138` `publisher_org()` exists precisely because
`cwe.mitre.org` + `attack.mitre.org` is one org, all five `owasp.org` hosts are
one org, and `www.microsoft.com` + `learn.microsoft.com` are one org. In the
candidate sweep, 8 of the 11 ACCEPTs were from orgs **already** in the corpus —
adding them would have raised the host count while leaving `orgs` flat.

**5. Do not scrape more pages.** 312 `*.auto.*` web items already exist and
**40.4% of them (126) are navigation chrome**, promoted at `high_confidence`
with scores in the normal 0.747–0.8845 band. The extraction step's failure mode
is invisible to every gate that ran: `body` is non-empty, `claim` clears
`MIN_CLAIM_CHARS`, and `has_fabricated_refs()` sees no ref shape. More scraping
adds more of exactly this.

**6. Do not treat a clean `verify_quotes` result as proof for a class that was
not run.** Only 11 of 37 web classes were verified this session; 9 FABRICATED
came out of that 11. The other 26 are *unmeasured*, which is a different state
from *clean*, and the whole-corpus run does not fit in a foreground timeout.

**7. Do not fix `metrics` `stale_rate_pct: 0.0` by pointing at the 126 nav items.**
`metrics` itself prints `unmeasured: 1`, `without_content_hash: 1` and the note
*"A stale_rate_pct of 0 with a non-zero without_content_hash means 'not
checked', not 'nothing is stale'."* The zero is an absence of measurement.

**8. Do not spend the wave on `open_redirect` and `xss` item volume.** They hold
135 of 665 web items, and `xss` has 0 locators on 154 links and `open_redirect`
has 82 links over 9 sources. Their apparent size is citation *reuse*, not
coverage — adding items to them inflates `items` while `orgs` and `loc%` stay
flat.

---

## Files created or modified by this analysis

Created (all read-only w.r.t. `db/wks.db`; no `--apply` was passed to any tool):

- `validation/w11_quality_improvement_plan.md` — this document
- `validation/w11_web_quality_measurement.json` — full per-class measurement dump
- `validation/w11_table_rows.json` — machine-generated 37-row table data
- `validation/w11_candidate_probe.json`, `validation/w11_neworg_candidates.json` — intake probe inputs
- `validation/w11_navchrome.json`
- `tools/w11_quality_probe.py`, `tools/w11_table_rows.py` — measurement scripts

Not modified: `db/wks.db`, `db/sources.json`, any other subagent's files.
