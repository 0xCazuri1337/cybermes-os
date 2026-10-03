# Validation Gates

The hard gates a finding must clear before it is knowledge.

## The four hard gates

These are **necessary conditions, not inputs to a weighted score**. A weighted
mean can be passed by a short, fluent, confident claim; a gate cannot.

| Gate | Rejects | Implemented in |
|---|---|---|
| `NO_SOURCES` / `INSUFFICIENT_SOURCES` | a claim with no provenance | `wks/quality.py` |
| `INSUFFICIENT_PUBLISHER_HOSTS` | two pages on one host counted as corroboration | `wks/quality.py` |
| `DISCOVERY_ONLY_SOURCE` | social media as knowledge (a lead, not a source) | `wks/quality.py` |
| `FABRICATED_REFS` | invented cross-references (`Ref1`, `Source2`) — **reject**, never downgrade | `wks/quality.py` |

Plus one gate outside the database: **every cited quote must actually appear on
the cited page** (`wks/verify_quotes.py`). A subagent reporting that it read a
source is a self-report and carries no weight.

## Why publisher hosts and not citation counts

Two pages on `owasp.org` are one publisher. The metric that matters is the
number of distinct registrable hosts behind a claim — measured on the previous
system, where 37 of 54 competencies could never corroborate because every seed
sat on `cwe.mitre.org`.

## States

`discovered → under_review → supported → high_confidence`, with `disputed`,
`outdated`, `rejected` and `unresolved` as legitimate terminal-ish states.
Unresolved is never presented as established.

## Checking

```bash
python -m wks.cli selftest     # the gate regressions
python -m wks.cli gate         # re-assess every item
```

`quality.py` is the **only** writer of `validation_state`. Nothing else may set
it.
