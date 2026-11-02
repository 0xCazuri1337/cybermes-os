# Un-rolled-back workflow credit to redeemable financial loss

> goal: `Accumulate a durable credit through repeated start-then-abandon workflow cycles and redeem it against a real order, producing realised financial loss without ever tendering payment.`
> generated from `db/wks.db` — edit the rows, not this file

A business workflow that grants a durable credit at an intermediate step and does not roll it back when the transaction is abandoned becomes a repeatable accrual loop, which becomes financial loss the moment the accumulated balance is redeemable.

## Impact

Direct financial loss to the merchant, produced by a sequence of individually unremarkable start and cancel operations rather than a malformed request.

## Sequence

### 1. Start a purchase or enrolment workflow to the point where the account is credited, then abandon or cancel the transaction instead of tendering.

**Why it works:** WSTG requires the effects of an incomplete step to be rolled back or canceled, and states the attack that this requirement exists to stop: an attacker may start transactions and cancel them to build their point levels without actually buy anything.

### 2. Repeat the start-then-cancel cycle until the accumulated credit is large enough to matter, then redeem the balance against a real order.

**Why it works:** CWE-841 states that by performing actions in an unexpected order, or by omitting steps, an attacker could manipulate the business logic of the product or cause it to enter an invalid state, so the stored balance becomes an invalid state that the redemption path trusts.
