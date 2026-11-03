<!-- GENERATED from db/wks.db — do not edit -->
# Race Conditions / TOCTOU

## Definition

Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.

- **CWE:** CWE-367
- **OWASP:** A04:2021
- **Surface:** business
- **Aliases:** ["race condition", "toctou", "time of check time of use", "double spend", "concurrent request limit bypass"]

Canonical home for `race`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

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

**The damaging form of a race is proven when an invariant that admits exactly one winner - a single remaining seat, one discount per order, one balance to spend - is satisfied twice by concurrent requests, because the response bodies show two winners and the persisted state shows the duplicated spend.**

A lost counter increment is a correctness defect; a duplicated reservation is a business one, and only the second is worth reporting as a security issue. The distinction is that the endpoint enforced the invariant once per request and never made the enforcement itself exclusive, so each request saw the invariant holding and passed. The artifact is therefore a pair of 200 responses each asserting the same scarce resource was granted, captured together with the state read-back that shows the spend counted twice - negative inventory, a coupon applied twice, a balance driven below zero. The hunter's test is to drive the endpoint to the boundary, then fire the requests simultaneously with all but one precondition met; the CWE-362 exclusivity property is what fails, and the report should say plainly which of the two guarantees the endpoint was missing, since the fix depends on which one.

*Disproof:* The claim is false when only one of the concurrent requests is granted the resource and the others receive an explicit conflict, refusal or retry signal, which is the behaviour a correct allocation must show. It is also false where the duplicated effect is intentional and idempotent - applying the same discount to the same order twice is designed behaviour - where the two responses belong to different users who were each entitled to their own allocation, and where the apparent double-spend is a display-layer artefact such as a cached total rather than a persisted balance.

**A concurrent attempt that is deliberately aborted is the disproof of the finding: when one of two simultaneous writes is rejected because the value it read had changed, the endpoint enforced its invariant atomically and the race does not exist.**

Optimistic concurrency turns the race into a detectable event, and the hunter must read that event correctly instead of retrying past it. The pattern is a watch-then-write: the caller marks the fields it depends on, reads the current value, and commits its write; if anything changed in between, the commit is refused rather than applied against a stale read. Redis documents both halves - watched keys are monitored to detect changes, and if one is modified before the commit the whole transaction aborts and returns a null reply to signal failure. So the reportable artifact for a protected endpoint is the pair of outcomes, one write applied and one explicitly refused, not two successes. If a tester's harness silently retried the aborted request until it succeeded, it manufactured the winning outcome it then reported as a race, so the abort has to be surfaced in the evidence.

*Disproof:* The disproof is void - the race stands - when both writes are applied despite the second having observed a changed value, which means the check was not enforced; when the abort is only advisory and the caller proceeds on a stale read anyway; when the comparison key is unrelated to the value actually written, so nothing that mattered was watched; and when the two requests were never concurrent in the relevant sense, one having fully completed and committed before the other read.

**A race condition is proven when two requests issued concurrently against the same object both return success but the final state reflects only one of the two intents, because the read that decided what to write and the write itself were not atomic.**

This is the artifact a reviewer can re-run: fire N identical read-modify-write requests at once, have every one return 200, and then show that the resulting value accounts for fewer than N increments. Success codes are not evidence of correctness here, which is exactly why the finding needs the state read-back - the two observations only contradict each other if you compare what was promised against what persisted. CWE-362 defines the defect as a code sequence requiring temporary exclusive access to a shared resource while a timing window exists in which another concurrent sequence can modify it, so the hunter's job is to locate that window and widen it. Redis's own documentation supplies the clean model: a read followed by a write works reliably only for a single client, and with two clients both reading 10 and both writing 11, the final value is 11 instead of 12. Deterministic reproduction normally needs both barriered concurrency and repetition, because an unrepeated win is not yet proof of a window.

*Disproof:* The claim is false when the final state accounts for every concurrent intent, which is what a correct implementation should produce - a compare-and-set, a unique constraint, a serialisable transaction, or an atomic single-key increment. It is also false where the two writes genuinely did not overlap in time, where the endpoint serialises them by design, where the writes target different objects and were never in contention, and where the apparent loss is an artefact of the test harness - a client-side rate limit, a queue that dropped a request while still reporting success, or a caching layer serving a stale read.

**A check-then-act sequence - validate a permission, a price, a state flag or a balance, then act on the value that check returned - is proven exploitable when acting on the earlier value succeeds after the check, because the artifact is a state transition that the check that was supposed to authorise it no longer describes.**

TOCTOU is the shape most worth hunting because it survives the fixes that close the obvious races. CWE-370 tracks exactly this pattern, and its mapped attack pattern is described as leveraging a time-of-check and time-of-use window; the sequence reads as a pair of operations with attacker-controllable latency between them, and the second operates on the world as the first saw it. The hunter's artifact is a state transition that should have been impossible - a permission revoked between check and act, a coupon expired after validation, a seat taken after the availability read, a file replaced between the permission check and the write - with the check's own response captured alongside it. Widening the window is a legitimate technique, but the report must show the underlying two-step pattern rather than just the padding, because a fix that only slows the attack leaves the class intact.

*Disproof:* The claim is false when the act re-reads and re-validates rather than using the earlier value, so a change between check and act causes refusal instead of success; when the pair is genuinely atomic at the storage layer, as a compare-and-swap or a conditional write; when the resource being acted on is not attacker-influenceable between the two operations; and when the observed transition is one the endpoint is entitled to perform regardless of the check's outcome, in which case the check was advisory and no invariant was violated.

## Exploitation

**A race condition (CWE-362) is a code sequence requiring temporary exclusive access to a shared resource while a timing window exists in which another concurrent code sequence can modify it.**

CWE-362 defines the general defect: a concurrent code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence operating concurrently. The attacker's job is to locate that window and widen it. The harm is indirect: the window is the primitive that every race-derived bypass, double-spend, and TOCTOU exploit rides on, so the hunt starts by finding where a read and a write are not atomic together.

*Disproof:* Refuted where there is no timing window: the resource was accessed by a single sequence only, the shared resource is not actually shared across threads, no concurrent write raced the read, or an authoritative source shows the described interleaving cannot occur.

**TOCTOU (CWE-367): a check-then-act race where a second operation uses a stale value of what the first check returned, surviving fixes that close the obvious race.**

TOCTOU is the shape most worth hunting because it survives the fixes that close the obvious races. The sequence reads as a pair of operations with attacker-controllable latency between them, and the second operates on the world as the first saw it. The artifact is a state transition that should have been impossible - a permission revoked between check and act, a coupon expired after validation, a seat taken after the availability read, a file replaced between the permission check and the write - with the check's own response captured alongside it.

*Disproof:* Refuted when the act re-reads and re-validates rather than using the earlier value, so a change between check and act causes refusal instead of success; when the pair is genuinely atomic at the storage layer, as a compare-and-swap or a conditional write; when the resource being acted on is not attacker-influenceable between the two operations.

**Lost update: two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.**

POST /api/wallet/transfer and POST /api/account/balance both read balance then write balance-amount with no row lock. Fire 20 concurrent transfers of 10 from a 100 balance: the balance check passes 10 times, each write is balance = <stale read> - 10, and the final balance reflects only the last thread's subtraction. Audit this wherever a numeric field is read in one statement and written in another - balance, stock, seats_left, quota, credit.

*Disproof:* If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.

**A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.**

The precondition that makes a race a race: the server passes through a sub-state where the code still looks unused - a promo unused, a coupon unexpired, a token unconsumed. Same shape for gift cards, CAPTCHA solutions, brute-force counters, stock and reservation slots, and any POST /api/queue|exports|payouts with no server-enforced idempotency token. If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.

*Disproof:* If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.

**Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter; two requests usually suffice to prove impact.**

The window is often milliseconds and unpredictable, so the big burst is for discovery; two requests usually suffice to prove impact. Use Burp Repeater: 20 tabs of the same request, Send group in parallel (HTTP/1 uses last-byte synchronisation; HTTP/2 uses the single-packet attack). Turbo Intruder: engine=Engine.BURP2, concurrentConnections=1, queue 20 copies with gate='1', then engine.openGate('1').

*Disproof:* If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.

**Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question.**

ikelihood that it will be exploited to
 achieve a different impact. 
 
 
 Impact 
 Details 
 
 
 
 
 
 
 
 
 Alter Execution Logic; Unexpected State 
 
 
 
 
 
 
 Scope: Integrity, Other 
 
 
 
 The attacker can gain access to otherwise unauthorized resources. 
 
 
 
 
 
 
 
 
 Modify Application Data; Modify Files or Directories; Modify Memory; Other 
 
 
 
 
 
 
 Scope: Integrity, Other 
 
 
 
 Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question. 
 
 
 
 
 
 
 
 
 Other 
 
 
 
 
 
 
 Scope: Integrity, Other 
 
 
 
 The resource in question, or other resources (through the corrupted one), may be changed in undesirable ways by a malicious user. 
 
 
 
 
 
 
 
 
 Hide Activities 
 
 
 
 
 
 
 Scope: Non-Repudiation 
 
 
 
 If a file or other resource is written in this method, as opposed to in a valid way, logging of the activity may not occ

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Race conditions such as this kind may be employed to gain read or write access to resource".

**Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread**

the variety of ways in which this
 weakness can be introduced. It is not a complete list of all CVEs that are related to this CWE entry. 
 
 
 
 
 Reference 
 Description 
 
 
 
 
 
 
 
 CVE-2015-1743 
 
 
 
 
 TOCTOU in sandbox process allows installation of untrusted browser add-ons by replacing a file after it has been verified, but before it is executed 
 
 
 
 
 
 
 
 CVE-2003-0813 
 
 
 
 
 Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread 
 
 
 
 
 
 
 
 CVE-2004-0594 
 
 
 
 
 PHP flaw allows remote attackers to execute arbitrary code by aborting execution before the initialization of key data structures is complete. 
 
 
 
 
 
 
 
 CVE-2008-2958 
 
 
 
 
 chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks. 
 
 
 
 
 
 
 
 CVE-2008

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads t".

**chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.**

hain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread 
 
 
 
 
 
 
 
 CVE-2004-0594 
 
 
 
 
 PHP flaw allows remote attackers to execute arbitrary code by aborting execution before the initialization of key data structures is complete. 
 
 
 
 
 
 
 
 CVE-2008-2958 
 
 
 
 
 chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks. 
 
 
 
 
 
 
 
 CVE-2008-1570 
 
 
 
 
 chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of prote".

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

**Bypass: single-use token consumption flag written after the side effect - replaying the privileged action in parallel before the flag commits wins the race.**

Two bypass shapes. (1) Order of operations: the handler validates the invite/reset token, performs the privileged action, and only then sets tokens.used_at - racing widens an already-open window, so replay 20 parallel POST /api/invites/accept with the same token. (2) Idempotency scoping: an Idempotency-Key table keyed on (key) or (key, session_id) lets you bypass by changing one byte of the key or firing from a second session/tab with a copied key; per-(user, operation) scoping does not.

*Disproof:* If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation.

**Bypass: idempotency keys scoped per session (rather than per operation) allow duplicate application because the uniqueness check is not exclusive across the raced window.**

An idempotency implementation that scopes the dedup key on session rather than on (user, operation) is weaker: a second tab or a second session holding a copied key passes the duplicate check. The race is deterministic - fire parallel requests with the same idempotency key from two concurrent sessions and the action is applied twice because the check is scoped too narrowly. The fix is to scope the key per (user, operation) and enforce uniqueness atomically.

*Disproof:* If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation (session-scoped or not).

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

**To decide this case, observe: Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.**

Derived from race.fp.verify_concurrency_reached_origin, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (race.fp.verify_concurrency_reached_origin) states the full boundary.

## Impact

**Race impact scales with what the single-use resource gates: money, stock, or a security control - and it is often under-detected.**

Grade by the gated resource: balance/transfer = direct financial loss; stock or seat reservation = oversell plus price pressure on real users; CAPTCHA or rate limit = the control is bypassed and the protected endpoint (login, OTP, enumeration) becomes brute-forceable; single approval = two people sign off one payment. CWE-367 notes resources written outside the valid path may escape logging, so attach downstream state evidence, not HTTP traces.

*Disproof:* If the raced action caused no money, stock or control bypass and downstream records match normal single-use behaviour, the demonstrated impact is negligible.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/362.html>
  - <https://cwe.mitre.org/data/definitions/367.html>
  - <https://cwe.mitre.org/data/definitions/370.html>
- **hackerone.com** (disclosure)
  - <https://hackerone.com/reports/1717650>
- **owasp.org** (taxonomy)
  - <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>
  - <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/logic-flaws>
  - <https://portswigger.net/web-security/logic-flaws/examples>
  - <https://portswigger.net/web-security/race-conditions>
- **postgresql.org** (writeup)
  - <https://www.postgresql.org/docs/current/transaction-iso.html>
- **redis.io** (writeup)
  - <https://redis.io/docs/latest/develop/using-commands/transactions/>
- **sqlite.org** (writeup)
  - <https://sqlite.org/isolation.html>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
