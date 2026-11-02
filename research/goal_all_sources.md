# GOAL — learn ALL remaining sources into domains/, then gap-check web/network/AD

Honest status at the time of writing: HackTricks is harvested (72 items,
live-verified). Everything else is fetched or indexed but NOT yet in the db.
The user interrupted to correct exactly this, so the remaining work is written
down as checkable criteria rather than assumed.

## Sources the user supplied (9 total)

| # | source | scope the user gave | state |
|---|---|---|---|
| 1 | hacktricks.wiki | web + network + AD | **DONE** — 72 items, 144/144 quotes live-verified |
| 2 | Notion `Rem01x Red Teaming Journey` | all EXCEPT mobile + wireless; **labs INCLUDED** | indexed, MCP blocked, public fetch works |
| 3 | Notion `Web Penetration Testing` (sedate-session-3ae) | everything | indexed, same |
| 4 | Notion `Methodology` (app.notion.com/p/Methodology-…) | web | not fetched |
| 5 | kathan19 HowToHunt GitBook | everything | **85/85 pages fetched**, 16 classes mapped, 55 quotes verified, **0 items in db** |
| 6 | oreobiscuit Bug Bounty Playbook GitBook | everything | **116/116 pages fetched**, 10 classes mapped, 17 quotes verified, **0 items in db** |
| 7 | pentester.land/writeups | everything | JSON index fetched: **6421 writeups**, 664 bug tags |
| 8 | sploitus.com | CVEs | llms.txt read; site asks not to be bulk-crawled (has /api + sitemap) |
| 9 | cvebase.io | CVEs | probed: no llms.txt, /api 404s |

## CRITERIA

- **C1** Every source above is either HARVESTED into the db, or recorded in
  `research/source_queue.md` with the MEASURED reason it cannot be (a refusal
  reason, never silence).
- **C2** Every harvested item's quote verifies against the LIVE web.
  Check: `python tools/ht_live_verify.py` → `quote_mismatch 0`.
- **C3** `python -m wks.ingest` (never `--dry`, never `--no-verify`) merges, and the
  promoted count is re-derived FROM THE DB.
- **C4** Every promoted item is rendered on a page under `domains/`.
  Check: the drift assertion in `tools/ht_diag6.py` → `missing: 0`.
- **C5** `domains/web/htb-techniques.md` and its network twin are resolved: the
  cross-class material is either (a) demonstrably duplicated into the class
  pages so the flat file adds only ordering, or (b) removed. No page may be the
  ONLY home of knowledge that belongs to a class.
- **C6** Before/after report: items_total, high_confidence, per-class counts,
  per-domain counts, all measured before and after.
- **C7** Gap check for web, network and AD, reported as a ranked table with the
  next concrete command for each gap.

## RULES for the remaining sources

1. **GitBook and Notion are PRACTICE guides.** Two gitbook hosts are one genre,
   not two publishers. The corroborating partner must be NORMATIVE
   (portswigger/owasp/mitre/rfc/httpwg/w3/nvd), never another hunter guide.
2. **pentester.land is an INDEX, not prose.** It ships `writeups.json` with 6421
   entries. A tag like `local privilege escalation` (245 write-ups) is not a
   claim; it is a **frequency signal** — where the ecosystem actually finds
   things. Use it to set priority and to register the privesc classes that do not
   exist yet. Do NOT fetch 6421 write-ups.
3. **CVE databases are templates, not knowledge.** One page per CVE, same shape.
   That is the MODULE_FILLER shape the relevance gate rejects. A CVE is a
   `variant`/`signal` item filed under the MECHANISM class. Filing CVEs as
   classes would create thousands of junk classes.
4. Quotes are sliced, never typed; asserted with `find_quote` before staging;
   partner quotes recycled from already-promoted items on a different
   registrable domain; heading furniture (`¶`, `#`) refused.
5. Respect sploitus' stated terms: use `/sitemap.xml` or the API, not HTML bulk
   crawling. Attribution required if anything is quoted.

## Ordering (the user asked for all sources, then gaps — not gaps now)

1. Harvest HowToHunt packets -> items (waves of 2 children)
2. Harvest Biscuit packets -> items (waves of 2 children)
3. Fetch + harvest the Notion sub-pages (web_extract; MCP has no access)
4. pentester.land JSON -> frequency analysis -> privesc class registration
5. sploitus / cvebase -> sitemap/API, or record the measured refusal
6. Re-verify live, re-render domains/, resolve C5
7. Before/after report (C6)
8. Gap check web / network / AD (C7)