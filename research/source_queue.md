# SOURCE INGESTION QUEUE — learned material -> domains/

Every source the user asked to learn from, with what I measured about each.
Status is honest: `INDEXED` means I have the page list; `FETCHED` means the raw
markdown is on disk; `HARVESTED` means it passed quote verification into the db.

## Sources

| # | source | scope | pages | status |
|---|---|---|---|---|
| 1 | HackTricks `hacktricks.wiki` | web + network + AD | 1066 in scope | **HARVESTED** — 72 items promoted, 144/144 quotes live-verified |
| 2 | Notion — Rem01x Red Teaming Journey | everything except mobile + wireless; labs INCLUDED | ~60 sub-pages | INDEXED (MCP lacks access; public web fetch works) |
| 3 | Notion — Web Penetration Testing (sedate-session-3ae) | everything | ~60 sub-pages | INDEXED (same) |
| 4 | Notion — Methodology (app.notion.com/p/Methodology-…) | web | ? | NOT FETCHED |
| 5 | GitBook — kathan19 HowToHunt | everything | **85 pages** | INDEXED via `llms.txt` (fetch loop failed — see below) |
| 6 | GitBook — oreobiscuit Bug Bounty Playbook | everything | ~90 pages | INDEXED via `llms.txt` |
| 7 | sploitus.com | CVEs | ? | NOT FETCHED |
| 8 | cvebase.io | CVEs | ? | NOT FETCHED |

## What works for each host type (measured)

- **GitBook**: `<host>/llms.txt` returns the FULL page index with `.md` URLs, and
  every page is served as clean raw markdown at `<url>.md`. This is the good path
  — no HTML, no nav chrome.
- **Notion**: the MCP `notion_fetch` 404s on every one of these pages
  (`object_not_found`, integration `1f8d872b…` not granted). The pages ARE public
  — plain `web_extract` on the site URL returns the content. **Use web_extract for
  Notion, not the MCP.** Sub-pages are not enumerable from the parent page's
  markdown, so each needs its own URL.
- **sploitus / cvebase**: unmeasured. Do not assume an llms.txt.

## Fetch bug to avoid (measured)

A `while read url; do curl -o hth_NNN.md ...; done` loop wrote **0 files and
returned code 000 for all 85 URLs**. Cause: the loop ran in a directory the shell
could not write (`cd "$TMPDIR"` resolved oddly under MSYS), so every `-o` target
failed. **Rule: fetch from a Python script writing into an absolute native path,
never a bash loop with a relative `-o` target under MSYS.** MSYS path translation
is disabled on this host, so native tools need `C:/…` paths.

## Anti-fabrication rules that apply to ALL of these (unchanged)

1. A quote is SLICED from the fetched page, never typed.
2. Every quote is asserted with `wks.verify_quotes.find_quote` before staging.
3. **These are PRACTICE guides, not normative sources.** HowToHunt, Biscuit's
   playbook and the two Notion notes are all hunter-written methodology. GitBook
   and Notion are single publishers — an item citing `kathan19.gitbook.io` plus
   `oreobiscuit.gitbook.io` is still ONE editorial genre and must not be counted
   as two independent publishers for corroboration.
4. The partner quote is RECYCLED from an already-promoted corpus item on a
   different registrable domain, so the 2-publisher rule is met honestly.
5. Reject partner quotes carrying heading furniture (`¶`, `#`) — measured defect.
6. Re-verify everything from the LIVE web at the end, not from cache.

## Pipeline to reuse

The HackTricks run already built and proved the whole chain:

```
llms.txt / page list        -> <src>_xwalk.py       map pages -> classes
raw .md pages               -> <src>_fetch.py       cache to disk
class-relevant sentences    -> <src>_packets.py     VERIFIED quotes + recycled partner
                             -> <src>_brief.py      flat brief per child
2 children (rate limit)     -> authored claims + disproof + kind
                             -> ht_audit_claims.py  parent re-audits D1-D4
                             -> ht_stage.py         re-verifies, builds intake
                             -> wks.ingest          THE GATE (never --dry)
                             -> ht_live_verify.py   live re-fetch from the internet
                             -> taxonomy_write.py   regenerates domains/
```

## Classification rule for the CVE sources (7, 8)

CVE databases are NORMATIVE-ish but very uniform: one page per CVE, same template.
That uniformity is exactly the "MODULE_FILLER" shape the relevance gate rejects.
So a CVE page is **not** a claim — it is a `signal`/`variant` item filed under the
MECHANISM class it belongs to (e.g. a Windows named-pipe impersonation CVE is a
`variant` under privesc, not a class of its own). Filing CVEs as classes would
create thousands of junk classes.

## Known corpus state at the start of this queue

- 1631 items, 985 high_confidence, 62/62 classes have a `class_domain` row.
- **Zero privilege-escalation classes** — sources 2, 5 and 6 all carry privesc
  material (Biscuit's has a whole Thick Client / DLL Hijacking / IoT section),
  so this gap gets closed during the next waves rather than after them.