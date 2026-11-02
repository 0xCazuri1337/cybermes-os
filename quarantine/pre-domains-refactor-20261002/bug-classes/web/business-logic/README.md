# Business logic — correct steps, wrong order or wrong number

## What this directory represents

Every individual request is handled correctly. The flaw is in the sequence, the
invariant, or the arithmetic across requests.

## What belongs inside it

`workflow-bypass.md` (**canonical for the class**), `race-condition.md`,
`price-manipulation.md`, `payment-logic.md`, `coupon-abuse.md`,
`state-machine-flaws.md`.

## What does NOT belong inside it

- A missing authorisation check → `../authorization/` (the check is absent, not
  mis-sequenced)
- Payment gateway integration bugs owned by the processor

## How children are organised

`workflow-bypass.md` and `state-machine-flaws.md` are the general forms; the
rest are concrete, testable instances (price, payment, coupon). `race-condition.md`
is canonical for TOCTOU and is the one class here with a timing prerequisite.

## Related bug classes

Every chain in `../../attack-chains/business-logic-chains.md` starts here,
because business-logic findings are low-severity alone and severe when chained.

## How new entries should be added

Only for an invariant that is neither a state transition nor a numeric field.
A new discount type is a `coupon-abuse.md` variation.
