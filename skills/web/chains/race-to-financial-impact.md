# Race condition to duplicate fulfilment or discount abuse

> goal: `financial`
> generated from `db/wks.db` — edit the rows, not this file

A check-then-act window on a single-use resource lets concurrent requests all pass the check before any of them writes, multiplying the effect of one entitlement.

## Impact

Direct financial loss: one coupon applied N times, stock oversold, or a payment confirmed on an order that was already fulfilled.

## Sequence

### 1. Identify the endpoint where the limit is enforced in application logic rather than a database constraint

**Why it works:** A UNIQUE index or a single transaction closes the window; without that gap there is nothing to race.

**Requires:** a coupon, stock, reservation or single-use token

**Backed by:** `race.prereq.check_then_act_single_use_limit`

**This step fails if:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.

### 2. Fire a fixed burst of concurrent identical requests at that endpoint

**Why it works:** A burst widens the probability of overlapping the window; two requests are frequently not enough to hit it.

**Backed by:** `race.tech.parallel_burst_thread_count`

**This step fails if:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.

### 3. Check whether the guarded counter advanced once or N times

**Why it works:** This is the finding. Successes far exceeding the increment is the invariant break that cannot happen single-threaded.

**Backed by:** `race.validation.counter_moved_once`

**This step fails if:** If the counter incremented once per success (20 increments for 20 successes), the limit was enforced atomically and no race occurred.

### 4. Apply the raced entitlement to a checkout or fulfilment to convert the invariant break into measurable loss

**Why it works:** Impact must be priced. A counter that moved twice is a bug; two discounted orders shipped is a payout.

**Backed by:** `race.chain.coupon_race_to_financial_damage`

**This step fails if:** If the 20 raced checkouts all charged the undiscounted total and the promo ledger shows a single redemption, the race produced no financial gain and the chain does not hold.
