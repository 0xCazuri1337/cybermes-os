# Race Conditions / TOCTOU

> surface: `business` · CWE: CWE-367 · OWASP: A04:2021
> maturity: **mature** — 15 items, 15 supported, 3 FP rules, 2 chains

Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.

**Aliases:** race condition, toctou, time of check time of use, double spend, concurrent request limit bypass

## Prerequisite

- **Checkout endpoints that validate payment and confirm the order as two steps of one request leave the cart mutable inside that window.**  
  `high_confidence` · score 0.861 · disproved by: If the order row snapshots line items at payment validation, later cart writes never reach the confirmed order and paid total equals shipped total.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
- **A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.**  
  `high_confidence` · score 0.8335 · disproved by: If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## Signal

- **Responses exposing a remaining/quantity counter, or endpoints returning 200 once then an error on immediate replay, mark a limited resource.**  
  `high_confidence` · score 0.9125 · disproved by: If a second identical sequential call returns the same 200 with a merely decremented counter, the resource is multi-use and no race exists.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions> · <https://portswigger.net/web-security/logic-flaws/examples>

## Technique

- **Sequence races - one request type in a burst followed immediately by a second request type - catch multi-endpoint windows that single-endpoint bursts miss.**  
  `high_confidence` · score 0.861 · disproved by: If only one order in the burst carries the discount and later orders show the full price, the two windows never aligned and no chain occurred.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
- **Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter.**  
  `high_confidence` · score 0.8335 · disproved by: If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- **Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.**  
  `high_confidence` · score 0.806 · disproved by: If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- **Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads t".
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
- **chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of prote".
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
- **Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Race conditions such as this kind may be employed to gain read or write access to resource".
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>

## Validation

- **Prove the race by breaking an invariant single-threaded use cannot reach: negative balance, two votes from one account, more items shipped than paid for.**  
  `high_confidence` · score 0.8965 · disproved by: If sequential repeats return 409 and the parallel run leaves the invariant intact, the invariant is enforced and there is no race.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- **A race is proven when N parallel identical calls all return success yet the guarded counter advanced by exactly one.**  
  `high_confidence` · score 0.8335 · disproved by: If the counter incremented once per success (20 increments for 20 successes), the limit was enforced atomically and no race occurred.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## Fp Rule

- **Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.**  
  `high_confidence` · score 0.861 · disproved by: If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>

## Impact

- **Race impact scales with what the single-use resource gates: money, stock, or a security control - and it is often under-detected.**  
  `high_confidence` · score 0.8335 · disproved by: If the raced action caused no money, stock or control bypass and downstream records match normal single-use behaviour, the demonstrated impact is negligible.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>

## Bypass

- **Single-use tokens whose consumption flag is written after the side effect, or idempotency keys scoped per session instead of per operation, lose the race deterministically.**  
  `high_confidence` · score 0.8335 · disproved by: If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation.
  sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## Chain Link

- **Chaining a limit-overrun race into a financial or fulfilment effect - oversold stock, duplicated fulfilment, repeated referral credit - is what converts the bug into a payable finding.**  
  `high_confidence` · score 0.806 · disproved by: If the 20 raced checkouts all charged the undiscounted total and the promo ledger shows a single redemption, the race produced no financial gain and the chain does not hold.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>

## False-positive rules

- **Hypothesis:** Two simultaneous coupon redemptions both succeeded
  - **Invalidated by:** The sequential baseline produced the identical result, and per-request nonces were distinct, so the requests never overlapped at the origin
  - **Rule:** Prove concurrency before claiming a race: single-threaded baseline plus distinct origin timings, otherwise you measured your own tooling

- **Hypothesis:** Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.
  - **Invalidated by:** If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
  - **Rule:** Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.

## Related classes (via chains)

- `bizlogic` Business Logic Flaws (3 chains)
