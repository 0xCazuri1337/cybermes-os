# Deliberation round 03 — three-model debate on `path_traversal`

- participants: P1 nemotron-3.5-lightning (advisory lens), P2 ling-3.1-flash
  (standards lens), P3 mimo-v2.6-flash (practitioner lens)
- 16 claims proposed, 13 distinct, 5 self-rated high, 10 flagged DISPUTE
- 3/3 participants produced a critique AND an expression of uncertainty
- **artifacts:** `runtime/loop/deliberation/round-03/` (per-turn raw text,
  `claims.json`, `summary.json`)

## What the debate actually settled

### 1. Cross-lens CONVERGENCE: verification requires content, not a status code
This is the round's strongest result, and it emerged from a **direct
contradiction**, not from agreement.

- P3 CLAIM 3 (self-rated **high**): "A blind traversal attempt can be scored
  from the status line alone when the server returns 403 for paths resolving
  outside the document root and 404 for in-root misses."
- P2 CLAIM 3 (self-rated medium): "A path_traversal finding is confirmed under
  the normative rule **only when returned content is verifiably from outside the
  intended directory**, so distinct status codes, error text, or timing alone are
  heuristic signals, not proof of CWE-22."
- P1, cross-examined, sided with P2: status codes "are heuristic signals at
  best, not proof of CWE-22" — servers "vary widely" and proxies/error handlers
  can produce differential statuses with no file ever read.
- **P3 then retracted its own high-confidence claim** in turn 2, naming the
  mechanism it had glossed over: "logging, proxy rewriting, and error handlers
  can produce distinct statuses with no file ever read."

A high-confidence claim was talked *down* by cross-examination. That is the
single most valuable thing this loop does, and no amount of solo generation
would have produced it.

### 2. Cross-lens CONVERGENCE: encode-then-validate ordering
P1 and P2 independently converged on the same mechanism from opposite lenses:
P1 framed it as "normalization occurs after the allowlist comparison" (TOCTOU),
P2 as "any string-level check must canonicalize before comparing and a
mis-ordered canonicalization recreates the escape." Same failure, two vocabularies.

### 3. A hallucination CAUGHT and refuted
P1 CLAIM 2 claimed Windows `\.` "device name components" bypass `../`-filters by
"increas[ing] the escape depth." P3 refuted it correctly:

- `\.` is a **no-op** relative segment, not a device name (CON/PRN/AUX/NUL/COM1).
- A no-op segment cannot add escape depth — only `..` does.
- Strip every `\.` and the payload behaves identically.
- The real mechanism is the **backslash separator** (a `/`-splitting filter never
  sees a traversal), which is P3's CLAIM 1 — P1 had rediscovered the mechanism
  and mislabeled its cause.

P3 also caught that P1 CLAIM 1 was "internally inverted": the allowlist matches
on the full string with `.jpg` while the KERNEL truncates at `\x00`, not the
application truncating after.

**Neither P1 claim may enter the corpus.** This is precisely why the loop needs
more than one perspective: a fluent, confident, well-cited-sounding claim was
wrong on the mechanism, and one peer caught it in a single round.

## Convergence metric: the first version was a FALSE signal

The initial convergence counter reported **47 "convergences"** — because it
counted shared words like `path`, `file`, `directory`, `base`. That is domain
vocabulary, not agreement; every claim in this class contains those words.

With domain terms stop-listed, the threshold sweep gives a truthful picture:

| bar (distinctive shared terms) | pairs |
|---|---|
| >= 2 | 20 |
| >= 3 | 6 |
| >= 4 | 4 |
| >= 5 | 3 |

The 4 pairs surviving >= 4 are the ones reported above: two genuine convergences
and one contradiction. **A metric that cannot distinguish agreement from shared
jargon will report a debate as maximally convergent when it is actually
contradicting itself.**

## Claims still OPEN (not verified, not in the corpus)
Every claim here is unverified model output. None has been quote-checked against
a live source, so none may be ingested. The highest-value follow-ups:

1. The content-not-status-code verification rule is now the corpus's best
   candidate for a `validation` item — it needs 2 independent publishers.
2. P3's backslash-separator claim (backslash defeats a `/`-splitting filter) is
   the surviving half of refuted P1 CLAIM 2 and is worth verifying on its own.
3. P1 CLAIM 1's null-byte class is real historically but the claim's stated
   mechanism is inverted; it needs rewriting before it is worth citing.

## Remaining uncertainties
- Whether the 3 free models share blind spots. They disagreed productively here,
  but all three are small models; the corpus's best material still comes from
  the in-process executor with live sources.
- No participant cited a URL or quote. The debate generates HYPOTHESES; the gate
  and live fetching remain the only path to corpus items.
- Claude Code (v2.1.221) is installed and would be the ideal fourth voice, but
  answers `Credit balance is too low` — so the loop is a genuine three-way
  debate, not a four-way one.