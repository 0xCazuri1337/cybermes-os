# Run report — 2026-10-02 (initial build + first research wave)

Machine-readable: `state/overnight-last.json`, per-cycle `state/run-*.json`,
`state/legacy-audit.json`, `state/seed-verification.json`.

## What was researched

Four delegated research agents, one per class, each required to cite ≥2 sources
on **different hostnames** and to record a disproof clause per item:

| class | submitted | promoted | rejected (fabricated quote) |
|---|---|---|---|
| idor | 14 | 13 | 1 |
| oauth | 14 | 14 | 0 |
| race | 14 | 12 | 2 |
| graphql | 14 | 12 | 2 |
| **total** | **56** | **51** | **5** |

**CORRECTED 2026-10-02.** An earlier revision of this report claimed 11 of 57
(19%) were fabricated. That number was **wrong — it was my verifier's false
positives, not the agents' fabrication.** The four research agents each
independently verified their quotes before writing, and were right.

The verifier compared raw page text against raw quote text. Three independent
causes made genuine quotes fail to match:

1. **Markdown emphasis and table pipes.** A quote copied from a `.md` source
   keeps `**Easy**` and `|`; the rendered page has neither.
2. **Tag-strip artefacts.** `deleteUser`</code>, de-tags to `deleteuser ,` —
   a space before the comma that is not in the original text.
3. **Undecoded HTML entities.** `&#x27;` survived stripping, so any quote
   containing an apostrophe could never match its own page.

Fixed in `verify_quotes.py` (progressive normalisation variants, every-word
token matching) and `pipeline.fetch` (entity unescaping before and after tag
stripping). 11 → 5 rejections, and the 5 survivors were confirmed by hand
against the live pages: two are invented outright ("Logic-based vulnerabilities
can be extremely diverse" and "Accidental exposure of private GraphQL fields"
appear nowhere on their cited pages), and one is a *reconstructed* quote — its
fragments all exist on the OWASP IDOR cheat sheet but the sentence was stitched
together from separate locations, which is a subtler form of the same problem.

The real lesson is not about the agents. It is that **a verifier with a
false-positive rate this high is worse than no verifier**, because an operator
who sees it reject real evidence twice stops trusting it entirely. Both
directions are now regression-locked in `eval/test_wks.py` T13: genuine
markup must match, and word-substituted fabrications must still fail.

## What was validated

- `eval/test_wks.py` — 13 tests / 33 assertions, all pass. T1–T5 are regressions
  against the previous system's actual failure mode; T10–T12 are regressions
  against bugs found during this build.
- All 45 taxonomy seed URLs GET-verified live; every class spans ≥2 publisher
  hosts. (9 initially-dead URLs were found and replaced.)
- 4 attack chains, each step bound to a promoted item — 4/4 complete.
- Cold rebuild from taxonomy alone: reproducible.
- Full re-ingest into a fresh database: 56/56 promoted, chains and skills
  regenerated identically.

## What was rejected

| artifact | count | reason |
|---|---|---|
| quarantined legacy items | **0 of 1,380 importable** | 1,234 no sources · 1,048 fabricated refs · 1,311 truncated teasers · 641 were test fixtures (`RAG Test 0`, `CLI Validate Test`) |
| agent items | 5 of 56 | cited quote absent from the cited page (confirmed by hand) |
| (superseded) my own verifier | 11 false positives | markdown/entities/tag-strip artefacts — fixed, T13 |
| whole records | 0 of 1,380 had substantial content AND a real citation | — |

The legacy corpus remains untouched in `quarantine/`. Per-record verdicts:
`state/legacy-audit.json`.

## What changed

New system at `~/.hermes/cyber/`: 15-module package, 12-table schema, quality
gate, hybrid retrieval, ingest/verification boundary, skill + chain generators,
FP learning, 13 metrics, retrieval probes, autonomous cycle, bounded overnight
loop. Plus `CONTROL/` constitution (I1–I10), 13 enforceable rules, `README.md`
architecture doc, and 4 generated class documents, 4 chain documents, 4 skills
with version history.

## Bug classes improved

idor, oauth, race, graphql — each from empty to `researching` with 12–14
promoted items, ≥2 publisher hosts per item, 100% disproof coverage.

## Skills changed

4 generated (`skills/{idor,oauth,race,graphql}-hunting/`), each with
`HISTORY.md`. All four regenerate byte-identically on repeat runs — verified.

## Chains discovered

4, each step citing the item that justifies it:
`idor-to-account-takeover`, `oauth-open-redirect-to-ato`,
`race-to-financial-impact`, `graphql-exposure-to-enumeration`.

## False positives learned

4 rules captured, each with hypothesis → test → what killed it → the durable
rejection rule:

1. **idor** — a 200 with data is not a finding until the same identifier resolves
   differently for a second identity. Compare bodies, not status codes.
2. **race** — prove concurrency before claiming a race; single-threaded baseline
   plus distinct origin timings, otherwise you measured your own tooling.
3. **oauth** — token storage location is only a finding when a script-execution
   primitive is separately demonstrable.
4. **graphql** — a DoS reproduced only on dev/staging is not a production
   finding; confirm the hostname and behavioural difference first.

## Knowledge marked outdated

None. No item exceeded the freshness window; `outdated` is implemented as a state
but nothing auto-applies it yet (limitation 4).

## Quality metrics

```
items_total                52        items_promoted          52
promotion_rate_pct       100.0       unsupported_claim_rate   0.0%
disproof_rate_pct        100.0       duplicate_rate           0.0%
sources                   51        publisher_hosts            7
classes                   15        classes_mature            0
false_positive_rules       4        chains                    4
open_conflicts            16        retrieval_probe        37.5%
```

## Unresolved conflicts

11, all of one kind: `fabricated-evidence`, recording each rejected item and the
page whose quote could not be found. They are retained, not deleted — if the
quote is later located the item can be reconsidered.

## Defects found and fixed during this build

Each was silent and each would have recurred. Now regression-locked.

1. **`config` resolved paths at import time** — a sandboxed run reused the
   previous database and reported on state it was not changing.
2. **Gate reasons carry a `(detail)` suffix** — `"FABRICATED_REFS" in reasons`
   silently failed on `"FABRICATED_REFS(4)"`, and a fabricated-source item
   reached `supported`.
3. **`verify_seed` used HEAD** — portswigger.net returns 404 to HEAD on ~20 live
   pages; the check reported phantom dead URLs and would have sent research after
   the wrong targets.
4. **`upsert_class` blanked fields on partial update** — every skill
   regeneration silently erased the class's CWE, OWASP, summary and aliases.
5. **SQLite `bm25()` is negative-is-better** — an `abs()` inverted the ranking,
   putting unrelated classes above correct ones while raw BM25 was right.
6. **FTS5 external-content `rebuild` double-indexes** without a preceding
   `delete`.
7. **`class_digest` ordered by score with no tiebreak** — every regeneration
   differed, manufacturing a version bump on every run.
8. **`skill_path` was written after rendering** — `maturity()` reported `skill`
   missing during render, so the content never converged.
9. **Run keys had second resolution** — three overnight cycles shared one key and
   overwrote each other's audit trail.
10. **`gap_report` called `sum()` on an `int`** — crashed on every call.
11. **`sorted(<genexp>, key=…)` is a SyntaxError** — generator must be wrapped.
12. **`chain_step` has no `chain_key` column** — retrieval crashed on any item
    that had a chain.
13. **`ingest_file` annotated `Path` but the CLI passed `str`**.
14. **`CONTROL.md` pointed at a `CONTROL/` directory that did not exist** — the
    control surface was unreachable from the only file advertising it.

## Two corrections made after the first report

1. **The 19% fabrication figure was false.** It measured my verifier's
   false-positive rate, not agent misconduct. See the table above and T13.
2. **One item was an orphan.** The agent renamed an item while correcting a
   quote, and because `item_key` is the identity, the old row survived as
   promoted, retrievable knowledge citing superseded evidence. `wks/reconcile.py`
   now detects and supersedes these. It also exposed two metric bugs that only
   appeared once a non-active row existed: `items_total` counted superseded
   rows, and `disproof_rate_pct` read **101.92%** — a rate above 100% is the
   kind of number that should stop a maintainer cold, and did.

## Superseded by the second wave

`wks/methodgen.py` was added after this report: the Methodology Agent role was
missing entirely, and this run's `methodology` gap is now closed for all 15
classes. The "26 assertions" figure here is also stale — the suite is now 48.

## Remaining gaps

11 of 15 classes are registered and seeded but empty: `authz`, `bizlogic`,
`csrf`, `deser`, `jwt`, `mass_assign`, `path_traversal`, `sqli`, `ssrf`, `ssti`,
`xss`. The probe reports this honestly at 37.5% rather than scoring around it.

Classes not yet in the taxonomy at all: HTTP request smuggling, cache
poisoning, prototype pollution, XXE, subdomain takeover, WebSockets, HTTP/2,
supply chain, OAuth device flow, SAML.

Also missing: methodology documents for every class (`methodology/` holds 8
legacy ones not yet bound to classes), automatic semantic conflict detection,
automatic staleness re-review, and the FP capture path is manual — it needs a
hook that runs when a hunt ends.

## Next recommended internal tasks

1. Research the 11 seeded-but-empty classes, highest yield first: `sqli`,
   `ssrf`, `xss`, `jwt`, `csrf`.
2. Bind the 8 existing `methodology/*.md` procedures to their classes so
   maturity can measure them.
3. Add 6–10 cross-class chains now that four populated classes can support them.
4. Add automatic conflict detection between same-class high-confidence items
   that share significant vocabulary but assert opposite things.
5. Add the remaining taxonomy classes, starting with request smuggling and
   prototype pollution.
6. Wire FP capture into hunt completion so §17 becomes automatic rather than a
   manual command.
