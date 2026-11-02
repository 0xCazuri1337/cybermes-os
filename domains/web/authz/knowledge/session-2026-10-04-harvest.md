# Session debrief — 2026-10-04 (aggregator-harvest classes)

This note covers five classes that each gained exactly **one** item in this
session, all from the same production path:
`authz`, `exposed_services`, `mass_assign`, `misconfig`, `supply_chain`.

Each has its own per-class debrief where more was learned
(`open_redirect`, `path_traversal`, `smuggling`, `xss`, `linux_privesc`).

## What was added

| class | item | state | why it matters |
|---|---|---|---|
| `authz` | `authz.lead.bbd_bobdahacker.com` | promoted 0.79 | self-registration onto a data platform granting access that should require an invitation |
| `exposed_services` | `exposed_services.lead.bbd_silentsignal.eu` | promoted 0.77 | unauthenticated management-plane RCE (IBM i Management Central) |
| `mass_assign` | `mass_assign.lead.bbd_varonis.com` | **HELD** `OFF_CLASS_TOPIC` | AI agent trust boundary — see below |
| `misconfig` | `misconfig.lead.bbd_brutecat.com` | promoted 0.79 | AI-driven discovery of 1,500 exposed APIs / 3,600 keys |
| `supply_chain` | `supply_chain.lead.bbd_flatt.tech` | promoted 0.82 | one GitHub issue compromising any repo using a Claude Code workflow |

## Read every one of these as an anchor, not as knowledge

All five came from the `bugbountydaily` aggregator: the RSS body is a bare list
of links with no prose, so it is registered as `source_type='index'` and is
**never citable**. The linked ARTICLE is the publisher. Each item cites the
article plus one independent partner found by `tools/correlate_leads.py`, and
every quote was re-verified against the live page before ingest.

The claims are topic labels — *"Public writeup evidence for supply_chain: CI
workflow -> supply chain."* The mechanism, the disproof clause and both verbatim
quotes are in the item bodies and in each `DIGEST.md`. `HUNT.md` maps each to a
procedure shape. A one-line note is the honest ceiling on what a topic label is
worth; these are retrieval anchors with verified provenance.

## The one item the gate refused — and why that is the system working

`mass_assign.lead.bbd_varonis.com` is **held with `OFF_CLASS_TOPIC`**, not
promoted. The article is about an AI agent's trust boundary, which is not mass
assignment. It passed every other check — the quote verified live on the cited
page, two independent publishers agreed, the body met the length floor — and was
still refused because the *topic* was wrong for the class it was filed under.

This is the class of failure a 2-host rule alone does not catch: a real,
correctly-quoted, well-sourced claim filed in the wrong place. It stays held
rather than being quietly reassigned, because guessing the right class is
exactly what the gate exists to prevent. If it is genuinely mass assignment
somewhere in the article, a human should file it deliberately.

## Production path and what it cost

`tools/harvest_bugbountydaily.py` harvested 8 leads from the feed; each was
quote-verified against live bytes; `tools/correlate_leads.py` paired 8 with an
independent second publisher; the gate promoted **7 and held 1**. Three bugs in
my own harvest tooling surfaced during that run and are fixed: mapping keyed on
raw hosts instead of registrable domains (3 articles silently unmapped), the host
parsed with `re.split(r"/+", url)[2]` (every article read as `UNMAPPED blog`),
and a 58-character span accepted until a 90-character floor was added.

Three partner URLs were **404** on first use — two moved, one was a wrong path.
A 404 is a moved page, not a fabrication; each was replaced with a verified-live
successor (CWE-915 for mass assignment, CWE-444 for smuggling, the OWASP
Deserialization sheet for supply chain).