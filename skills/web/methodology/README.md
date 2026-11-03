# Methodology

**How to approach** a class of problem. A procedure, not a payload list.

## What belongs here

Ordered hunts. Every step states what to do **and what would disprove the
hypothesis** — a test that cannot fail proves nothing.

## What does NOT belong here

- Vulnerability definitions → [`bug-classes/`](../../README.md)
- Payloads and evidence → `db/wks.db` (canonical), `learning/knowledge/`
- Class→procedure mappings are generated into `derived/`

## How children are organised

Two kinds of file, deliberately:

- **`*-hunting.md` / `*-testing.md`** — entry points. They give the *order* of
  work and name the canonical class pages rather than restating them.
- **`derived/`** — one generated page per registered class, produced by
  `python -m wks.methodgen` from the `bug_class` table in `db/wks.db`.

`scripts/` holds the checkers that make the coverage claim falsifiable.

## Entry points

| Entry point | Covers |
|---|---|
| [recon.md](recon.md) | reconnaissance |
| [web-hunting.md](web-hunting.md) | a full web target, in order |
| [api-hunting.md](api-hunting.md) | a full API target, in order |
| [authentication-testing.md](authentication-testing.md) | the identity boundary |
| [authorization-testing.md](authorization-testing.md) | the access boundary |
| [injection-testing.md](injection-testing.md) | the interpreter boundary |
| [business-logic-testing.md](business-logic-testing.md) | sequence and invariant |

## Reading order

1. **Recon** first. Every other procedure assumes an attack surface.
2. **Authentication / authorization** next. Highest yield, most mis-validated.
3. **Injection** once you know the sinks and contexts.
4. **Business logic** when the obvious classes came back clean.

## The rule that separates this from a checklist

Every step states what to do **and what would disprove it**. The "disproves"
clauses are the reason these are procedures rather than lists. Where a class
file carries a `Disproof:` line, that is the falsifier for its claims — see
[`validation/false-positives.md`](../../../validation/false-positives.md).

## Coverage check

`tools/taxonomy/check_methodology_coverage.py` maps class id →
procedure by reading `bug_class.methodology` from the canonical db, and reports
`covered / gaps / broken mappings / DUPLICATED / NON-PORTABLE`. An unreadable
registry exits non-zero rather than printing "all clear" — a silent zero is the
exact failure the check exists to catch.

## Related

- [`bug-classes/`](../../README.md) — what each class *is*
- [`attack-chains/`](../chains/README.md) — how classes combine
- [`validation/`](../../../validation/README.md) — what counts as proven