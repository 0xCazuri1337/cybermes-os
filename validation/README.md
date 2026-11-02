# Validation

**What counts as proven.** Separate from methodology (how to hunt) and from
knowledge (what is true).

## What belongs here

The hard gates a finding must clear, the evidence a report needs, and the
false-positive rules that reject a hypothesis before it wastes a report slot.

## What does NOT belong here

- Per-class rejection rules → those live in `db/wks.db` (`fp_case`) and render
  into each class file's *Common False Positives*
- Severity scoring → `reporting/severity.md`

## How children are organised

- `validation-gates.md` — the four hard gates and their implementations
- `evidence-requirements.md` — what a report must carry
- `false-positives.md` — rejection discipline, including testing the checker

## Related

- `CONTROL/rules.md` — R1–R13, each with how it is checked
