# False Positives

Rejecting a hypothesis before it costs a report slot.

## The rule

A rejection must say **why the evidence is not a finding**, not "this looks
intended". Each per-class rule lives in `db/wks.db` (`fp_case`) and renders
into that class file's *Common False Positives* section — this file is the
discipline, not the list.

## Distinguish two rejections

| Verdict | Meaning | Action |
|---|---|---|
| *unpromotable pending better evidence* | the claim may hold; the evidence is thin | hold, find a second publisher |
| *evidence is fabricated* | the quote is not on the page, or a ref is invented | **reject and fix the producer** — do not retry the same brief |

Collapsing these two is how a broken acquisition step gets mistaken for a thin
item, and gets retried forever.

## Test the checker in both directions

A rejection rate computed from an unvalidated verifier is a number about your
own bugs, not about the producer. Before trusting any rejection:

- genuine artifact + genuine quote → must **PASS**
- genuine artifact + one substituted word → must **FAIL**

The first implementation of the quote checker rejected 11 of 56 **genuine**
quotes — a 19% false-positive rate, all of it extraction bugs (markdown
emphasis, table pipes, undecoded HTML entities) and none of it agent
misconduct. A verifier that cries wolf gets switched off, and then it protects
nothing. `eval/test_wks.py` T13 pins both directions.

## If a rejection looks wrong

Diff the raw artifact before blaming the source. Three false-negative sources
live in the extraction, not the quote: markdown emphasis, table pipes, and
undecoded entities (`&#x27;`, `&quot;`). Unescape before stripping tags and
again after.

## Record it

Every rejection carries its reason. That log is the audit trail and the input to
fixing the producer — `wks/fp.py` captures hypothesis → test → invalidated-by →
rejection rule.
