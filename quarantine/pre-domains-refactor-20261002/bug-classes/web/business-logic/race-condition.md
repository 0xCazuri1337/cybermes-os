# Race Conditions / TOCTOU

## Definition

Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.

- **CWE:** CWE-367
- **OWASP:** A04:2021
- **Surface:** business
- **Aliases:** ["race condition", "toctou", "time of check time of use", "double spend", "concurrent request limit bypass"]

Canonical home for `race`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.**

Trace POST /api/cart/apply-promo or POST /api/redeem: (1) SELECT used_by, (2) recalc total, (3) UPDATE promotions SET used=1. The server passes through a sub-state where the code still looks unused. Same shape for gift cards, CAPTCHA solutions, brute-force counters, stock and reservation slots (single-use or rate-limited endpoints), and any POST /api/queue|exports|payouts with no server-enforced idempotency token.

*Disproof:* If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.

**Checkout endpoints that validate payment and confirm the order as two steps of one request leave the cart mutable inside that window.**

POST /api/checkout usually goes pending -> payment validated -> confirmed. Between validation and confirmation the cart is still live, so a parallel POST /api/cart/items in the same session ships items that were never paid for. Same for async splits: order created on request 1, capture on request 2. Also flag purchase, reservation and posting flows, where OWASP API6:2023 says excessive access does real business damage.

*Disproof:* If the order row snapshots line items at payment validation, later cart writes never reach the confirmed order and paid total equals shipped total.

## Attack Surface

Surface: **business**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Responses exposing a remaining/quantity counter, or endpoints returning 200 once then an error on immediate replay, mark a limited resource.**

Grep responses for remaining, stock, quantity_available, slots_left, uses_remaining, attempts_left. Send the endpoint twice in sequence: 200 then 409/410/422 means the limit is enforced by app logic, so it is raceable. Record the counter before and after a burst - if N parallel successes moved it by only 1, the check wrote once while N actions succeeded.

*Disproof:* If a second identical sequential call returns the same 200 with a merely decremented counter, the resource is multi-use and no race exists.

## Exploitation

**Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.**

POST /api/wallet/transfer and POST /api/account/balance both read balance then write balance-amount with no row lock. Fire 20 concurrent transfers of 10 from a 100 balance: the balance check passes 10 times, each write is balance = <stale read> - 10, and the final balance reflects only the last thread's subtraction. Audit this wherever a numeric field is read in one statement and written in another - balance, stock, seats_left, quota, credit.

*Disproof:* If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.

**Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter.**

Burp Repeater: 20 tabs of the same request, Send group in parallel. HTTP/1 uses last-byte synchronisation; HTTP/2 uses the single-packet attack. Turbo Intruder: engine=Engine.BURP2, concurrentConnections=1, queue 20 copies with gate='1', then engine.openGate('1'). The window is often milliseconds and unpredictable, so the big burst is for discovery; two requests usually suffice to prove impact.

*Disproof:* If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.

**Sequence races - one request type in a burst followed immediately by a second request type - catch multi-endpoint windows that single-endpoint bursts miss.**

Queue group A = 10x POST /api/cart/apply-coupon with promo=X, group B = 10x POST /api/checkout, both on the same gate so B fires as A drains. This is the coupon-then-checkout chain: every order placed in the window carries a discount that should have been single-use. Multi-endpoint windows drift apart because endpoints have different processing times, so warm the connection first (a harmless GET / before the group, single connection) and otherwise keep both groups identical in size.

*Disproof:* If only one order in the burst carries the discount and later orders show the full price, the two windows never aligned and no chain occurred.

## Variations

**Single-use tokens whose consumption flag is written after the side effect, or idempotency keys scoped per session instead of per operation, lose the race deterministically.**

Two bypass shapes. (1) Order of operations: the handler validates the invite/reset token, performs the privileged action, and only then sets tokens.used_at - racing just widens an already-open window, so replay 20 parallel POST /api/invites/accept with the same token. (2) Idempotency scoping: an Idempotency-Key table keyed on (key) or (key, session_id) lets you bypass by changing one byte of the key or firing from a second session/tab with a copied key; per-(user, operation) scoping does not.

*Disproof:* If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `limit-overrun-to-quantified-financial-loss` — Single-use entitlement limit overrun to quantified settlement over-issue (goal: `financial_loss`)
- `race-to-financial-impact` — Race condition to duplicate fulfilment or discount abuse (goal: `financial`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.**

Check two killers: your HTTP/1.1 client reused one keep-alive socket or the proxy capped concurrency, so nothing overlapped (parallel latency should be near sequential, not N times slower). Second, you hit an edge cache, not the origin - API8:2023 notes discrepancies across the server chain cause desync. Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.

*Disproof:* If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
**Hypothesis:** Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.
- Invalidated by: If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
- **Rejection rule:** Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.

**Hypothesis:** Two simultaneous coupon redemptions both succeeded
- Invalidated by: The sequential baseline produced the identical result, and per-request nonces were distinct, so the requests never overlapped at the origin
- **Rejection rule:** Prove concurrency before claiming a race: single-threaded baseline plus distinct origin timings, otherwise you measured your own tooling

## Validation

**Prove the race by breaking an invariant single-threaded use cannot reach: negative balance, two votes from one account, more items shipped than paid for.**

State the invariant first (balance >= 0; one vote per user per round; shipped <= paid; one approval per document per role). Run N=20 parallel requests, then query state with a read-only endpoint or second account. Report the delta, not the traffic: balance -450 after 500 units of concurrent transfers, 2 accepted votes from user 1337, 12 items on an order paid for 10. Then replay the same sequence single-threaded to show it is rejected.

*Disproof:* If sequential repeats return 409 and the parallel run leaves the invariant intact, the invariant is enforced and there is no race.

**A race is proven when N parallel identical calls all return success yet the guarded counter advanced by exactly one.**

Record GET /api/cart first (uses_remaining=0). Fire 20 parallel POST /api/redeem with the same code, then re-read state. Proof needs all three: >=2 responses carry the reduced total, the counter moved by 1 not 20, and the side effects appear N times (N orders, N gift-card draws). Log the full response set and the post-state; a counter that moved 20 times means you hit a multi-use code, not a race.

*Disproof:* If the counter incremented once per success (20 increments for 20 successes), the limit was enforced atomically and no race occurred.

## Impact

**Race impact scales with what the single-use resource gates: money, stock, or a security control - and it is often under-detected.**

Grade by the gated resource: balance/transfer = direct financial loss; stock or seat reservation = oversell plus price pressure on real users; CAPTCHA or rate limit = the control is bypassed and the protected endpoint (login, OTP, enumeration) becomes brute-forceable; single approval = two people sign off one payment. CWE-367 notes resources written outside the valid path may escape logging, so attach downstream state evidence, not HTTP traces.

*Disproof:* If the raced action caused no money, stock or control bypass and downstream records match normal single-use behaviour, the demonstrated impact is negligible.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/367.html>
- **owasp.org** (taxonomy)
  - <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>
  - <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/logic-flaws/examples>
  - <https://portswigger.net/web-security/race-conditions>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
