# Web hunting — entry point

The ordered approach for a web target, from surface discovery to a validated
finding. Each stage names its canonical classes rather than repeating them.

## Order

1. **Reconnaissance** — [recon.md](recon.md). Every later step assumes an
   attack surface exists.
2. **Authentication and authorization** — [authentication.md](authentication.md),
   [authorization.md](authorization.md), [idor.md](idor.md). Highest yield and
   the most frequently mis-validated; see
   [evidence-requirements.md](../validation/evidence-requirements.md).
3. **Injection** — [injection-testing.md](injection-testing.md), once you know
   the sinks and the contexts.
4. **Client-side and business logic** — when the obvious classes came back clean.

## Per-stage rule

Every step states what to do **and what would disprove it**. A step that cannot
fail is a checklist line, not a procedure — see
[false-positives.md](../validation/false-positives.md).

## The identification move

Harvest every identifier a response echoes back — `owner_id`, `user_id`,
`tenant_id`, `parent_id`, object keys. Those values, not arithmetic, are the
wordlist for every authorization sweep that follows.

## Related

- Classes: [`bug-classes/web/`](../bug-classes/web/README.md)
- Chains: [`attack-chains/`](../attack-chains/README.md)