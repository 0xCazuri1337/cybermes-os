# Report structure

A report exists so a triager can decide without asking you anything. Every
section below earns its place by removing a question.

## Order

1. **Title** — the flaw and the asset, not "Security Issue".
2. **Summary** — what an attacker can do, in one paragraph, no jargon needed.
3. **Severity and rationale** — see [severity.md](severity.md). The rationale is
   part of the severity, not an appendix to it.
4. **Affected asset** — the exact host, path, and parameter.
5. **Steps to reproduce** — numbered, from a clean session, using two accounts
   where the claim requires them.
6. **Evidence** — full request and response pairs. Not a description of them.
7. **Impact** — quantified to what you actually performed.
8. **Remediation** — the specific check that is missing, not "validate input".

## Rules

- No finding leaves this knowledge base without a **disproof clause**. A finding
  you cannot invalidate is a finding you cannot defend when challenged.
- A `200` with no second-identity comparison is not a reproduction.
- **Downstream state evidence, not an HTTP trace**, for anything involving
  timing or a counter. The trace proves the attempt; the resulting state proves
  the effect.
- Include what you tried that did **not** work. It saves the triager from
  re-testing and it shows the boundary was probed rather than guessed.

## What never goes in a report

- Speculative escalation that was not demonstrated. State it as a note.
- Bulk extraction, account enumeration or scope you did not actually perform.
  Labelled extrapolation is acceptable; presented as demonstrated is not.
- Lab-manufactured or environment-induced findings. Those are not evidence.

## Supersedes

`REPORT_FORMAT.md` was the original four-line short form. It has been
superseded by this file and archived outside the tree (2026-10-02 audit), so
nothing in `reporting/` links to a file that is no longer there.

## Related

- [severity.md](severity.md)
- [evidence-requirements.md](../validation/evidence-requirements.md)
- [false-positives.md](../validation/false-positives.md)