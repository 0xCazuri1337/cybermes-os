# Why the Notion items were NOT ingested

`TOTAL submitted=44 promoted=0 held=0 rejected=44`, every one
`QUOTE_NOT_FOUND_ON_CITED_PAGE`.

That is the gate working, not a bug and not fabrication. The gate re-fetches the
cited URL and re-checks the quote. Notion serves a **JavaScript shell**: a plain
HTTP fetch of the cited page returns **19,911 bytes containing zero 32-hex block
ids and none of the page's prose**. So the quote can never be found on the cited
page, by any verifier.

Measured:

    gate-style fetch of the cited Notion url : 19,911 bytes
    'IDOR' present in that body              : False
    block ids in that body                   : 0

The content exists — 102 prose pages were harvested through Notion's own API — but
the API is not the cited URL. Citing the API URL instead would be citing a
document nobody can read in a browser, and worse, it would teach the pipeline to
satisfy `find_quote` against a private endpoint. Neither is acceptable.

## The rule this establishes

**A citation must be re-verifiable by anyone who fetches it.** A source that
cannot be re-fetched as static text cannot back an item, no matter how good the
prose is. That is the same standard the HackTricks mirror had to meet
(`book.hacktricks.wiki` serves a byte-identical shell for unrelated paths), and
the same one GitBook passes by serving every page at `<url>.md`.

## What is kept

- `research/ans_not1.json`, `research/ans_not2.json` — the 44 authored claims,
  audited (44 PASS, 1 FAIL). They are real hunting knowledge and they are not
  lost; they are waiting for a citable home.
- `research/ht_audit.json` — the parent-side audit for this wave.
- `research/notion_rem01x_triage.json` — the page-by-page triage.
- `research/pk_notion.json` — 62 verified quotes, all asserted against the cached
  page text.

## How to close it properly

Re-source each claim against a citable page for the same mechanism. The mapping
is mechanical and already measured:

| Notion class | citable sources already in the corpus |
|---|---|
| `ad_kerberos` | MITRE T1558 / RFC 4120 / Microsoft (11 orgs already cited) |
| `ad_delegation` | SpecterOps, ired.team, RFC 4120 (11 orgs) |
| `csrf` | OWASP CSRF cheat sheet, PortSwigger CSRF (15 orgs) |
| `pass_the_hash` | MarcFredericGomez, ired.team, Microsoft (12 orgs) |
| `smb` | SpecterOps, MITRE, Microsoft, Tenable (11 orgs) |
| `xss` | OWASP, PortSwigger, W3C (14 orgs) |

So the wave should be re-run with `--partners` pointing at those normative pages:
the claim is authored once, and the evidence moves to a page that can be
re-verified. That is a re-run of `ht_stage.py` with different partner URLs, not
new research.

## What was NOT done

No threshold was lowered, no verifier was bypassed, and no citation was rewritten
to a URL that happens to contain the text. The 44 items are refused with the
reason recorded, which is the correct outcome for an unverifiable source.