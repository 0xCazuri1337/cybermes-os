---
name: race-hunting
description: Use when hunting Race Conditions / TOCTOU in a business target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Race Conditions / TOCTOU — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `business` · CWE CWE-367 · OWASP A04:2021
> evidence: 15 items, 15 supported, 3 FP rules, 2 chains
> maturity: **mature**

Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.

**Also called:** race condition, toctou, time of check time of use, double spend, concurrent request limit bypass


## Prerequisites (do not start without these)

- A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.
  - **Disproof:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- Checkout endpoints that validate payment and confirm the order as two steps of one request leave the cart mutable inside that window.
  - **Disproof:** If the order row snapshots line items at payment validation, later cart writes never reach the confirmed order and paid total equals shipped total.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>

## Recon signals (where to look)

- Responses exposing a remaining/quantity counter, or endpoints returning 200 once then an error on immediate replay, mark a limited resource.
  - **Disproof:** If a second identical sequential call returns the same 200 with a merely decremented counter, the resource is multi-use and no race exists.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions> · <https://portswigger.net/web-security/logic-flaws/examples>

## Techniques (what to change)

- Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question.
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Race conditions such as this kind may be employed to gain read or write access to resource".
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
- Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads t".
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
- chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of prote".
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
- Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.
  - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter.
  - **Disproof:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- Sequence races - one request type in a burst followed immediately by a second request type - catch multi-endpoint windows that single-endpoint bursts miss.
  - **Disproof:** If only one order in the burst carries the discount and later orders show the full price, the two windows never aligned and no chain occurred.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>

## Validation bar (how to prove it)

- Prove the race by breaking an invariant single-threaded use cannot reach: negative balance, two votes from one account, more items shipped than paid for.
  - **Disproof:** If sequential repeats return 409 and the parallel run leaves the invariant intact, the invariant is enforced and there is no race.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- A race is proven when N parallel identical calls all return success yet the guarded counter advanced by exactly one.
  - **Disproof:** If the counter incremented once per success (20 increments for 20 successes), the limit was enforced atomically and no race occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## False-positive rules (when to reject it)

- Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.
  - **Disproof:** If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>

## Impact framing

- Race impact scales with what the single-use resource gates: money, stock, or a security control - and it is often under-detected.
  - **Disproof:** If the raced action caused no money, stock or control bypass and downstream records match normal single-use behaviour, the demonstrated impact is negligible.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>

## Defence bypasses

- Single-use tokens whose consumption flag is written after the side effect, or idempotency keys scoped per session instead of per operation, lose the race deterministically.
  - **Disproof:** If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## Chaining opportunities

- Chaining a limit-overrun race into a financial or fulfilment effect - oversold stock, duplicated fulfilment, repeated referral credit - is what converts the bug into a payable finding.
  - **Disproof:** If the 20 raced checkouts all charged the undiscounted total and the promo ledger shows a single redemption, the race produced no financial gain and the chain does not hold.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>

## Rejected before you report

- **Two simultaneous coupon redemptions both succeeded**
  - Killed by: The sequential baseline produced the identical result, and per-request nonces were distinct, so the requests never overlapped at the origin
  - Rule: Prove concurrency before claiming a race: single-threaded baseline plus distinct origin timings, otherwise you measured your own tooling
- **Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.**
  - Killed by: If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
  - Rule: Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.

## Chains to

- `bizlogic` (3 shared chain(s))

---
Full class document: `skills/Web/race/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
