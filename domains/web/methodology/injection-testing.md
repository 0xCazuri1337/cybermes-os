# Injection testing

Procedure for the interpreter boundary. Classes live in
[`bug-classes/web/injection/`](../areas/web/injection/README.md).

## Order

1. **Find the sink before the payload.** An interpreter class needs a place where
   input is parsed; without a sink there is nothing to test.
2. **Identify the interpreter** — SQL, NoSQL, shell, template, LDAP. The escape
   rules and the blind-detection technique differ per language even when the
   flaw is structurally identical.
3. **Establish the boundary** with a value that is unambiguously data, so that
   a later structural test is unambiguous.
4. **Then go structural** — boolean pairs, time pairs, or error pairs depending
   on the interpreter. **One-sided tests prove nothing**: a true condition that
   changes the response and a false condition that does not.
5. **Confirm the side effect**, not just the response shape — that the query
   executed, that the command ran, that the filter matched.

## Why one-sided tests fail

A payload that returns a different response proves nothing on its own; the page
may have changed. The pair is what makes it evidence: same request shape, one
variable, opposite results.

## Disproof per step

Each class file's *Preconditions* section states what would disprove the
hypothesis — for injection, typically that the input is parameterised or
escaped at the sink rather than at the edge. Edge validation is not the control;
the sink is.

## Related

- [xss.md](xss.md) — the browser is also an interpreter
- [ssrf.md](ssrf.md) — the server as requester
- [../attack-chains/](../chains/README.md)