# Methodology — Business Logic

> Generated 2026-10-01T18:41:23Z. Competency id: `business-logic`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Abuse of the application's intended function. No input is 'malformed'; the sequence is.

## Procedure

 1. **Model the intended flow** — Write down what the feature is for, in the product's own terms, before testing it.
 2. **Identify the state machine** — Which transitions are legal, and what enforces each one.
 3. **Look for skipped steps** — Actions the UI gates but the API does not.
 4. **Look for repeated actions** — Coupon reuse, negative quantities, integer overflow in totals, replayed refunds.
 5. **Look for inverted logic** — Discount or refund paths where a larger input yields a smaller cost.
 6. **Test multi-tenant boundaries in the workflow** — Not just the object, but the sequence spanning tenants.
 7. **Test time and race conditions** — Two concurrent requests where the second should be rejected.
 8. **Rate-limit by business impact, not by request count** — Five hundred low-value requests may matter less than one high-value one.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- The server enforces the transition independently of the client.
- The invariant (total, balance, quota) holds under concurrency.

## Gates before this becomes a finding

- the abuse is demonstrated on a system you are authorized to test
- the business impact is quantified

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
