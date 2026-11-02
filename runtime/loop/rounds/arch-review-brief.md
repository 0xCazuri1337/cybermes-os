# ARCHITECTURAL REVIEW — attack this, don't agree with it

You are the **Deputy Lead / adversarial reviewer**. Hermes is Lead Architect.
Your job is to ATTACK the analysis below using evidence from the actual
repository. Find what is wrong, missing, or metric-gaming. Do not be agreeable.

## Repository
`C:/Users/Administrator/.hermes/cyber` — read files directly. WKS_ROOT is set.

## Baseline as reported (CHALLENGE EVERY NUMBER)
items 1693 (actual 1817) · promoted 1083 · classes 70 · conflicts "0" (actual
184 rows: 151 dismissed, 30 resolved, 3 open with a resolution fingerprint) ·
fp_case 88 · chains 79 · hunt entries 600 · top shape 451/600 (75%) ·
rubric 95/100 · maturity 55/70 = 78.57%

## What Hermes has ALREADY diagnosed (verify or refute each)
1. **Root cause of the 451/600 shape collapse**: `tools/playbook.py::classify()`
   returns a ranked list but only `[0]` is used, and the `http_param_probe`
   regex matches any HTTP-ish word, so almost everything lands there. Verify.
2. `wks/skillgen.py` has NO variation model — it renders promoted items by
   `kind` only. Verify.
3. `wks.cli metrics` counts conflicts as `status='open'` only, so "0" hides 184
   rows. Decide whether this is a real defect or correct semantics.

## What Hermes is about to do — ATTACK EACH
P1. Add a **variation model**: each hunt entry declares dimensions (technology,
   request location, parameter type, encoding, parser behaviour, auth state,
   proxy/caching, race window, bypass strategy, confirmation strategy) and the
   procedure branches on them.
   ATTACK: is this real variation or templated substitution with extra words?
   What stops it being 7 templates with 451 cosmetic variants?
P2. Add an **evidence entailment check** (quote -> claim) to the gate.
   ATTACK: entailment without an LLM is keyword overlap, which is gameable —
   a claim and a definitional quote share vocabulary. Is a lexical gate better
   than none, WORSE than none (false authority), or should it only DOWNRADE
   rather than promote?
P3. Make `dc2` coverage multi-dimensional (existence/evidence/procedural/
   operational/FP) instead of a count of 12 items.
   ATTACK: does this just move the goalposts? What stops it being a new number
   that also gets gamed?
P4. Keep orch as commander, wks as deputy; no re-parenting of modules.
   ATTACK: is that the right cut, or is it the source of the vocabulary split?

## Your deliverable
For EACH of P1-P4 plus the three baseline claims, give:
- **VERDICT**: sound / unsound / unsound-as-stated
- **The single strongest failure mode** you can find, with a concrete scenario
- **The simplest design that avoids it**
- **Evidence**: a file path + line, or a db query result

Prioritise findings that would make the system LOOK better while getting worse.
Name any place the current system is already gaming itself.

Then give your OWN top 3 highest-value engineering targets, ranked by
`impact on real hunting x confidence x breadth x persistence`. Be concrete.

Do NOT write any files. Reply with your analysis as text.