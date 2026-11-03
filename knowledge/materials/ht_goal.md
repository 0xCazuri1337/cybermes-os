# GOAL — Harvest HackTricks into the WKS corpus, routed by domain

## GOAL
Every in-scope HackTricks page (web, network-services, windows-hardening, linux-hardening,
generic-methodologies) is either mapped to an existing `bug_class` or recorded as a named
gap, and every class we route HackTricks into gains at least one **promoted** item whose
quotes verify verbatim on the live page — with no fabricated citation and no
single-publisher self-corroboration.

## CRITERIA (each checkable by a command)

- **C1 — mapping is complete and deterministic.**
  `python tools/ht_xwalk4.py` twice → identical JSON; 0 unmapped in-scope page is
  silently dropped (every one appears in `UNMAPPED` or `MATCHED`).
  Check: `python -c "import json;d=json.load(open('research/ht_crosswalk.json'));print(sum(len(v) for v in d.values()))"`
  → must equal 1066.

- **C2 — no item self-corroborates on HackTricks.**
  `hacktricks.wiki` and `raw.githubusercontent.com/HackTricks-wiki` are ONE publisher
  (`config.publisher_org` returns `hacktricks.wiki` / `github.com`, but the *pair*
  {hacktricks.wiki, github.com} is one editorial voice for this corpus).
  Every harvested item MUST cite HackTricks plus >=1 INDEPENDENT normative publisher.
  Check: `python tools/ht_verify.py` prints `self_corroborating=0`.

- **C3 — quotes are verbatim, extracted not written.**
  Every quote is sliced out of the fetched page and asserted with the gate's own
  matcher `wks.verify_quotes.find_quote` BEFORE the item is written. The build ABORTS
  on the first failure.
  Check: `python tools/ht_verify.py` prints `quote_mismatch=0`.

- **C4 — the merge is real, not a dry run.**
  Items reach the db through `python -m wks.ingest` (never `--dry`, never `--no-verify`),
  and the counts are re-derived FROM THE DB by the parent, not from a child's report.
  Check: `python -m wks.cli metrics` items_total rises; per-class counts re-read.

- **C5 — domain routing is wired, not assumed.**
  Every class touched resolves a domain via `wks.domains.domain_of`, and
  `python -m wks.domains --check` prints `tree check: 0 problem(s)`.
  Also: 22 registered classes currently have NO `class_domain` row (they resolve only
  via the surface fallback). Close that.

- **C6 — the tree is regenerated.**
  `python tools/taxonomy/taxonomy_write.py --check` reports 0 drift, so no class page
  hides rows that are in the db.

- **C7 — gaps are named, not guessed.**
  Every `UNMAPPED` page is either (a) attached to an existing class as a known
  alias/coverage note, or (b) emitted as a proposed NEW class with its
  target domain, so the gap list is actionable.

## NOT IN SCOPE
- The 403 `OUT_OF_SCOPE` pages (binary-exploitation, mobile, wifi, stego, hardware,
  blockchain, crypto, privacy, macOS, AI) — not requested.
- `todo/` — HackTricks' own unfinished stubs.
- Authoring `chains` or `fp_case` rows from HackTricks prose (not extractable; the
  existing gap-closing tools own that).

## ANTI-FABRICATION RULES THIS RUN ENFORCES

1. **Quote before claim.** Slices come from the page; the claim is written about the
   slice. No quote is typed from memory.
2. **Two hosts, two publishers.** `MIN_PUBLISHER_HOSTS = 2`. An item citing
   `hacktricks.wiki` + `raw.githubusercontent.com/...` counts as ONE publisher and is
   REJECTED by the builder, because it is the same document twice.
3. **Cite the source, not a viewer.** `raw.githubusercontent.com` is the file itself;
   `github.com/.../blob/...` returns 281KB of viewer markup that does NOT contain the
   quote (measured on a previous wave). Raw only.
4. **A 200 is not content.** Score each fetched page by whether it contains the class's
   vocabulary before spending a build slot; `book.hacktricks.wiki` serves a
   BYTE-IDENTICAL 9358-char shell for unrelated paths (measured), so it is refused.
5. **Concurrency 2.** Measured on this host: a 4-way wave lost 3 of 4 children to
   HTTP 429 with a single-route model. Waves of 2, mechanical extraction in the parent.