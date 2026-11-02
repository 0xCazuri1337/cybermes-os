# Business logic testing

Procedure for flaws where every individual request is handled correctly and the
flaw is in the sequence, the invariant, or the arithmetic. Classes live in
[`bug-classes/web/business-logic/`](../bug-classes/web/business-logic/README.md).

## Order

1. **Map the workflow** — every state, every permitted transition, every
   precondition. A bypass is a transition that should be unreachable.
2. **Map the invariants** in falsifiable form — balance >= 0; one vote per user
   per round; shipped <= paid; one approval per document per role.
3. **Test the sequence** — replay steps out of order, skip approvals, revisit a
   terminal state.
4. **Test the arithmetic** — negative quantities, price overrides, negative
   transfers.
5. **Test concurrency last** — [race-condition.md](../bug-classes/web/business-logic/race-condition.md). It needs an
   burst and produces the least reproducible evidence, so earn the right to it
   by exhausting the deterministic checks first.

## The evidence rule

Break an invariant that single-threaded use cannot reach, then replay the same
sequence single-threaded to show it is rejected.

For a race specifically, prove concurrency was actually reached **at the origin**:
put a unique nonce in every request and confirm they all come back with distinct
upstream timings. If your HTTP client reused one keep-alive socket, you measured
your own tooling, not the application.

## Why these findings need a chain

A business-logic finding is often low-severity alone and severe once applied to
money, stock, or a security control. Price the outcome: a counter that moved
twice is a bug; two discounted orders that shipped is a payout. See
[`business-logic-chains.md`](../attack-chains/business-logic-chains.md).

## Related

- [false-positives.md](../validation/false-positives.md)
- [reporting/severity.md](../reporting/severity.md) — pricing the impact