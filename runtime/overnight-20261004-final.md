# Overnight learning loop — final state (2026-10-04)

## Goal criteria: verified
| # | Criterion | Result | Evidence |
|---|---|---|---|
| C1 | Loop's own selector is wired | **PASS** | `wks.cli tasks` printed "no runnable task" over 18 claimable rows before; now prints `NEXT: hunt.proof.05.recon.tls [p1]` |
| C2 | Research tasks execute against live sources | **PASS** | wave 1 items 1679->1803; wave 2 `6 executed, stop=task_budget`, 6/6 ok, exit 0 |
| C3 | Corpus item count strictly increases | **PASS** | 1679 -> 1811 (+132) |
| C4 | No new open conflicts | **PASS** | `open_conflicts: 0` after every ingest |
| C5 | Gate regressions green | **PASS** | `wks.cli selftest` -> ALL WKS GATE TESTS PASS; self-audit healthy 20/20 |
| C6 | Quotes verify against live pages | **PASS** | 8/8 bugbountydaily quotes re-verified on their live pages (HTTP 200, span present) |

## Defect found and fixed first (before any research ran)
`wks` selected `status IN ('todo','doing')`; `orch` owns the canonical vocabulary
(`planned/ready/running/completed`) and rewrites the table on EVERY orchestrator
open. The two layers could not see each other's tasks: `next_task()` returned
`None` and `wks.cli tasks` reported "no runnable task" over 18 claimable rows —
while `orch.cli stopcheck` simultaneously said `ready: 18`. Same table, opposite
verdicts, no conflict reported.
- fixed in `wks/store.py` (next_task/claim_task/finish_task + normalise_task_status) and `wks/overnight.py` (select_tasks)
- locked by `eval/test_task_status_vocab_v2.py`: 19/19 PASS, both directions, including negative controls (child of a blocked / still-running / non-existent dep is still refused) and the original defect reproduced on the old filter.
- gate re-baselined with a stated reason; all 8 thresholds re-read and UNCHANGED.

## bugbountydaily.com added as a source — and used
It is an INDEX, not evidence: the RSS body is a bare link list with no prose, so
no quotable span exists. Registered `source_type='index'`, discovery-only; the
LINKED ARTICLE is the citable publisher.

Harvest → pair → gate:
- `tools/add_bugbountydaily_source.py` — registered feed + site as `index`
- `tools/harvest_bugbountydaily.py` — feed -> articles -> spans, each re-verified against the fetched bytes
- `tools/correlate_leads.py` — pairs each lead with a second INDEPENDENT publisher

**8 leads harvested, 8 paired, 7 promoted, 1 held, 0 conflicts.**
Classes: authz, misconfig, exposed_services, xss x2, smuggling, supply_chain.
Each promoted item cites 2 distinct publisher orgs and is retrievable
(`wks.cli search "blob url sandbox escape xss"` returns it at rel=0.965).

Three bugs of my own, each caught by measuring rather than assuming:
1. MAPPING keyed on raw hosts (`blog.ammaraskar.com`) -> 3 articles silently UNMAPPED. Keys must be registrable domains.
2. `re.split(r"/+", url)[2]` for the host -> every article read as `UNMAPPED blog`. `urlparse().netloc` is correct.
3. A 58-char span was accepted; `MIN_QUOTE` gate added (90ch).

## Honest limitation
The 7 promoted items carry TEMPLATED topic claims ("Public writeup evidence for
xss: Blob-URL sandbox escape to XSS") with the real mechanism in the body and a
verified quote on both sides. `claimcheck` passes them BY DESIGN — it detects
TRUNCATION, not vagueness. They are legitimate retrieval anchors and honest
evidence pointers, but they are weaker than the corpus's native items and should
be rewritten into falsifiable mechanism claims before being hunted from
directly.

## Still open (the loop will keep going)
36 tasks ready. Weakest classes unchanged in priority order:
windows_privesc_hijack(70), internal_recon(65), exposed_rmm(60),
service_enumeration(60), container_escape(50).
`stopcheck.should_stop=false`, so there is more useful work than budget.