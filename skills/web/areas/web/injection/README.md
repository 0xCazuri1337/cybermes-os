# Injection — attacker data interpreted as a language

## What this directory represents

One root cause with many interpreters: input that reaches a parser, evaluator or
command line without being constrained to data.

## What belongs inside it

`../../../sqli/CLASS.md`, `../../../nosql/CLASS.md`, `../../../cmd/CLASS.md`,
`../../../ssti/CLASS.md` (**canonical for SSTI**), `../../../ldap/CLASS.md`.

## What does NOT belong inside it

- Attacker data executed as script in a browser → `../xss/`
- Server-side template injection living at `../server-side/ssti.md` — that is a
  **pointer stub**; the canonical page is `../../../ssti/CLASS.md`
- A payload list → `methodology/injection-testing.md`

## How children are organised

One file per **interpreter**, because the escape rules, the sinks and the
blind-detection technique differ per language even when the flaw is identical.

## Related bug classes

Injection that *reads* server-side network state → `../request-forgery/ssrf.md`.
Injection into an ORM expression is SQL injection; injection into a template
engine is template injection.

## How new entries should be added

By interpreter, not by product. "Log4Shell" is command-injection-shaped; it is
a `../../../cmd/CLASS.md` variant, not a new class.
