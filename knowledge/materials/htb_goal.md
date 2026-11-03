# GOAL — HTB write-up technique corpus, sorted into web + network domains

**STATUS: MET.** 21 gated items merged, 0 rejected, both domains populated.

## Goal
Mine publicly-published Hack The Box machine write-ups for the techniques
operators actually meet, and fold those techniques into the WKS corpus as
gated items routed to the existing `web` and `network` domains — every claim
corroborated by a NORMATIVE (non-GitHub) publisher so no write-up ever
certifies itself.

## Why the anti-laundering fix came first
Every HTB write-up lives on GitHub. Before T25, `publisher_org()` split GitHub
into three "publishers" (`github.com` / `githubusercontent.com` /
`github.io`), so one repo citing itself in both forms satisfied
`MIN_PUBLISHER_HOSTS=2`. For a walkthrough corpus that is the DEFAULT case, not
an edge case. Collapsed to one org; blast radius measured FIRST (0 existing
items de-promote). Locked by T25, which asserts both the failure case and the
pass case so the fix cannot "pass" by disabling the check.

## CRITERIA — results

| # | Criterion | Required | Measured | Command |
|---|---|---|---|---|
| C1 | write-ups cached, real .md bodies | >= 150 | **512** (901,927 words, 6 repos) | `research/htb_corpus.json` |
| C2 | every write-up classified web/network | reconcile | web=94 network=418, reconcile OK | `classify_htb.py` |
| C3 | >= 2 distinct publisher ORGs per item | 2 | **0** items fail the gate | `python -m wks.cli gate` |
| C4 | <= 1 non-normative (GitHub) source per item | <= 1 | enforced + asserted in builder | `tools/htb_build_items.py` |
| C5 | every quote re-verifies live | 100% | **47/47 URLs, 0 failures** | live re-fetch + `find_quote` |
| C6 | items land in BOTH domains | both | web=**24** network=**8**, unplaced=0 | `tools/htb_domain_split.py` |
| C7 | class pages match the db | 0 problems | **0 across 62 classes** | `python -m wks.domains --check` |
| C8 | gate regression suite green | green | selftest PASS, T25 PASS, T26 PASS | `selftest`, `eval/test_*.py` |

Corpus movement: **1411 -> 1432 items, 827 -> 854 promoted (+21)**, disproof
coverage 100%, duplicate rate 8.24%.

## What landed (21 items / 19 classes)

WEB (12): path_traversal x3 (incl. one `bypass`), sqli, xss, ssrf, ssti, xxe,
idor, smuggling, file_upload, info_disclosure.

NETWORK / AD (9): service_enumeration, exposed_services, smb, ad_kerberos,
pass_the_hash, dns_enum, rdp, tunneling_pivoting, misconfig.

## Architecture (why the items are built this way)

    write-up (GitHub, 1 publisher, PRACTICE evidence: it shows the technique works in situ)
        + normative source (PortSwigger / OWASP / MITRE / RFC / vendor = MECHANISM evidence)
        -----------------------------------------------------------------------------------
        -> item gated on 2 ORGS, and the 2nd is authoritative, not another blog

A write-up alone can NEVER promote. That is the point: a walkthrough is one
person's account of one box. It earns the right to be CITED by proving the
technique is real in practice; the normative source carries the mechanism.

## Honest gaps (a gap became a new subgoal, not a stop)
- `nosql` and `ldap_enum` aborted: no cached module demonstrates their claim.
  Reported, not worked around — inventing a quote is the failure this corpus
  exists to prevent.
- 5 network classes remain `researching` (service_enumeration,
  service_enumeration_detail, ldap_enum, exposed_services, dns_enum): they had
  items but too few. Pre-existing, not caused by this wave.
- Wave-2a harvest was sent after 20 INVENTED repo names, all 404 (R11 again).
  The missing material turned out to be in the cache already — the builder's
  TOPICAL map simply had no entry for 6 classes. Fixed at the map, not by
  loosening the gate.

## Three real defects found and fixed (each with a test)
1. **GitHub self-corroboration** — one repo could satisfy the 2-publisher rule
   alone. `eval/test_github_publisher_collapse.py` (T25).
2. **`extract_text()` HTML-stripped markdown**, destroying literal `<script>`
   payloads so a correctly-quoted XSS item was reported FABRICATED. Fixed to
   be content-type driven. `eval/test_extract_text_markdown.py` (T26).
3. **The decode guard returned an EMPTY STRING for `application/x-txt`**, so
   every quote from such a source failed as "no evidence". Pre-existing; found
   by T26.

## NOT IN SCOPE
- Scanning, fuzzing, or exploiting anything (config.RESEARCH_ONLY stays True).
- Per-machine spoiler summaries (the corpus stores techniques, not box tours).
- Anything authored from memory without a fetched page to quote.

## WAVE PLAN (all complete)
  Wave 0 (done)  anti-laundering fix + T25 + blast radius + selftest
  Wave 1 (done)  harvest 512 write-ups + classify into web/network
  Wave 2 (done)  mine techniques, pair each with a normative source, build items
  Wave 3 (done)  merge through the gate, verify, project domains, audit
  Wave 4 (done)  gap analysis -> new subgoal -> TOPICAL map extended -> +5 items

## Reproduce
    python tools/htb_normative_report.py     # validate normative sources
    python tools/htb_fill_gaps.py            # derive phrases for gap classes
    python tools/htb_fix_phrases.py          # entity-trim + re-verify phrases
    python tools/htb_build_items.py          # build items (quotes sliced live)
    python tools/htb_audit_items.py          # D1-D4 audit of the EMITTED json
    python -m wks.ingest research/incoming/htb_<class>.json
    python tools/htb_domain_split.py         # web vs network, read from the db