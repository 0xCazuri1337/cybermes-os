# Business logic — correct steps, wrong order or wrong number

## What this directory represents

Every individual request is handled correctly. The flaw is in the sequence, the
invariant, or the arithmetic across requests.

## What belongs inside it

`../../../bizlogic/CLASS.md` (**canonical for the class**), `../../../race/CLASS.md`,
`../../../topics/business-logic/price-manipulation.md`, `../../../topics/business-logic/payment-logic.md`, `../../../topics/business-logic/coupon-abuse.md`,
`../../../topics/business-logic/state-machine-flaws.md`.

## What does NOT belong inside it

- A missing authorisation check → `../authorization/` (the check is absent, not
  mis-sequenced)
- Payment gateway integration bugs owned by the processor

## How children are organised

`../../../bizlogic/CLASS.md` and `../../../topics/business-logic/state-machine-flaws.md` are the general forms; the
rest are concrete, testable instances (price, payment, coupon). `../../../race/CLASS.md`
is canonical for TOCTOU and is the one class here with a timing prerequisite.

## Related bug classes

Every chain in `../../attack-chains/business-logic-chains.md` starts here,
because business-logic findings are low-severity alone and severe when chained.

## How new entries should be added

Only for an invariant that is neither a state transition nor a numeric field.
A new discount type is a `../../../topics/business-logic/coupon-abuse.md` variation.
