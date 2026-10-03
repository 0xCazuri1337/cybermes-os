# Single-use entitlement limit overrun to quantified settlement over-issue

> goal: `financial_loss`
> generated from `db/wks.db` — edit the rows, not this file

A check-then-act window on a single-use entitlement becomes a payable finding only once the duplicated effect is quantified at settlement rather than demonstrated as a duplicated response.

## Impact

Direct financial loss - discount dollars over-issued, limited stock oversold, or referral credit minted without the qualifying spend.

## Sequence

### 1. Run the sequential two-request baseline first and record whether the second sequential redemption is rejected.

**Why it works:** Without the sequential control a duplicated result cannot be attributed to concurrency; it may be your own connection pool serialising the burst, which is the standard false positive here.

**Backed by:** `bizlogic.fprule.single_interleaved_pair_is_not_a_race`

**This step fails if:** If the server enforces a uniqueness constraint or an idempotency key on the endpoint, the second request returning 409 Conflict is the control working, and the race claim is a false positive produced by a client that did not read the rejection as a rejection.

### 2. Locate the check-then-act window itself - the check, the applied effect, and the record update - that a concurrent pair can interleave across.

**Why it works:** The window between checking the single-use record and writing the updated record is the whole primitive; a single-use endpoint with no such window cannot be overrun.

**Backed by:** `race.prereq.check_then_act_single_use_limit`

**This step fails if:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.

### 3. Issue a parallel burst at the single-use endpoint sized to overlap the window, then read the used counter back from an independent session.

**Why it works:** Issuing multiple requests in quick succession to see whether the limit can be overrun is the documented procedure, and reading the counter from another session avoids trusting the response body of the raced request itself.

**Backed by:** `race.tech.parallel_burst_thread_count`

**This step fails if:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.

### 4. Scale the burst to a quantified number and compute the realised over-issue - discount dollars, item count, or credit balance - at settlement.

**Why it works:** The reportable figure is the money that actually moved, not the trace; a database uniqueness constraint rather than session state is the control whose absence let the burst succeed.

**Backed by:** `race.impact.inventory_and_control_bypass`

**This step fails if:** If the raced action caused no money, stock or control bypass and downstream records match normal single-use behaviour, the demonstrated impact is negligible.
