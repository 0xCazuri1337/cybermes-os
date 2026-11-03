# Methodology

> Generated 2026-10-01T18:41:23Z.

Methodology answers **how to approach a class of problem**. It is a procedure,
not a payload list — the evidence and sources belong in `db/wks.db`, and a
repeatable mechanised step belongs in a skill.

Each procedure below is ordered as a hunt: every step states what to do **and**
what would disprove the hypothesis, because a test that cannot fail proves
nothing. The "disproves" lists are the reason these are not checklists.

| Methodology | Covers |
|---|---|
| [authentication](authentication.md) | Authentication |
| [authorization](authorization.md) | Authorization / Access Control |
| [business-logic](business-logic.md) | Business Logic |
| [csrf](csrf.md) | CSRF |
| [idor](idor.md) | IDOR / BOLA (Object-Level Authorization) |
| [recon](recon.md) | Reconnaissance |
| [ssrf](ssrf.md) | SSRF (Server-Side Request Forgery) |
| [xss](xss.md) | XSS (Cross-Site Scripting) |

## Reading order

1. **Recon** first. Every other procedure assumes an attack surface.
2. **Authentication / Authorization / IDOR** next. Access control is the
   highest-yield web finding and the most frequently mis-validated.
3. **Injection classes** (XSS, SSRF) once you know the sinks and contexts.
4. **Business logic** when the obvious classes came back clean.

## Relationship to skills and knowledge

```
methodology/   the ordered approach        (this directory)
skills/        a mechanised repeatable step
db/wks.db      the gated claims, sources and disproofs they rest on
```

A methodology may cite a skill. A skill may not redefine a methodology.
Payloads and evidence live in `db/wks.db`, reached through `wks.cli`; there is
no un-gated payload library, because a payload with no provenance is exactly
the failure this system was built to stop.

## Registry alignment

Methodology pages are keyed to class ids in the `bug_class` table of
`db/wks.db`, so a class with no methodology is a visible gap rather than a
silent one. Run `tools/taxonomy/check_methodology_coverage.py`; it derives the
mapping from the db on every run, so there is no literal here to drift.
