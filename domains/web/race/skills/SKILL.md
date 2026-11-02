---
name: race-hunting
description: Use when hunting Race Conditions / TOCTOU in a business target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Race Conditions / TOCTOU — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `business` · CWE CWE-367 · OWASP A04:2021
> evidence: 25 items, 23 supported, 2 FP rules, 2 chains
> maturity: **mature**

Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.

**Also called:** race condition, toctou, time of check time of use, double spend, concurrent request limit bypass


## Prerequisites (do not start without these)

- A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.  _(merged 1 duplicate row(s))_
  - **Disproof:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- Checkout endpoints that validate payment and confirm the order as two steps of one request leave the cart mutable inside that window.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the order row snapshots line items at payment validation, later cart writes never reach the confirmed order and paid total equals shipped total.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>

## Recon signals (where to look)

- Responses exposing a remaining/quantity counter, or endpoints returning 200 once then an error on immediate replay, mark a limited resource.  _(merged 1 duplicate row(s))_
  - **Disproof:** If a second identical sequential call returns the same 200 with a merely decremented counter, the resource is multi-use and no race exists.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions> · <https://portswigger.net/web-security/logic-flaws/examples>

## Techniques (what to change)

- A race condition (CWE-362) is a code sequence requiring temporary exclusive access to a shared resource while a timing window exists in which another concurrent code sequence can modify it.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted where there is no timing window: the resource was accessed by a single sequence only, the shared resource is not actually shared across threads, no concurrent write raced the read, or an authoritative source shows the described interleaving cannot occur.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://portswigger.net/web-security/race-conditions>
- A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.  _(merged 1 duplicate row(s))_
  - **Disproof:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
- Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter.  _(merged 1 duplicate row(s))_
  - **Disproof:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter; two requests usually suffice to prove impact.  _(merged 1 duplicate row(s))_
  - **Disproof:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://portswigger.net/web-security/race-conditions> · <https://portswigger.net/web-security/logic-flaws>
- Lost update: two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.  _(merged 1 duplicate row(s))_
  - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://www.postgresql.org/docs/current/transaction-iso.html>
- Sequence races - one request type in a burst followed immediately by a second request type - catch multi-endpoint windows that single-endpoint bursts miss.  _(merged 1 duplicate row(s))_
  - **Disproof:** If only one order in the burst carries the discount and later orders show the full price, the two windows never aligned and no chain occurred.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
- TOCTOU (CWE-367): a check-then-act race where a second operation uses a stale value of what the first check returned, surviving fixes that close the obvious race.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the act re-reads and re-validates rather than using the earlier value, so a change between check and act causes refusal instead of success; when the pair is genuinely atomic at the storage layer, as a compare-and-swap or a conditional write; when the resource being acted on is not attacker-influenceable between the two operations.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://cwe.mitre.org/data/definitions/370.html> · <https://portswigger.net/web-security/race-conditions>
- Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.  _(merged 1 duplicate row(s))_
  - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## Tests

- To decide this case, observe: Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (race.fp.verify_concurrency_reached_origin) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>

## Validation bar (how to prove it)

- A race is proven when N parallel identical calls all return success yet the guarded counter advanced by exactly one.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the counter incremented once per success (20 increments for 20 successes), the limit was enforced atomically and no race occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
- Prove the race by breaking an invariant single-threaded use cannot reach: negative balance, two votes from one account, more items shipped than paid for.  _(merged 1 duplicate row(s))_
  - **Disproof:** If sequential repeats return 409 and the parallel run leaves the invariant intact, the invariant is enforced and there is no race.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws/examples>

## False-positive rules (when to reject it)

- Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>

## Evidence requirements

- A check-then-act sequence - validate a permission, a price, a state flag or a balance, then act on the value that check returned - is proven exploitable when acting on the earlier value succeeds after the check, because the artifact is a state transition that the check that was supposed to authorise it no longer describes.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the act re-reads and re-validates rather than using the earlier value, so a change between check and act causes refusal instead of success; when the pair is genuinely atomic at the storage layer, as a compare-and-swap or a conditional write; when the resource being acted on is not attacker-influenceable between the two operations; and when the observed transition is one the endpoint is entitled to perform regardless of the check's outcome, in which case the check was advisory and no invariant was violated.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://cwe.mitre.org/data/definitions/370.html> · <https://www.postgresql.org/docs/current/transaction-iso.html>
- A concurrent attempt that is deliberately aborted is the disproof of the finding: when one of two simultaneous writes is rejected because the value it read had changed, the endpoint enforced its invariant atomically and the race does not exist.  _(merged 1 duplicate row(s))_
  - **Disproof:** The disproof is void - the race stands - when both writes are applied despite the second having observed a changed value, which means the check was not enforced; when the abort is only advisory and the caller proceeds on a stale read anyway; when the comparison key is unrelated to the value actually written, so nothing that mattered was watched; and when the two requests were never concurrent in the relevant sense, one having fully completed and committed before the other read.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://sqlite.org/isolation.html>
- A race condition is proven when two requests issued concurrently against the same object both return success but the final state reflects only one of the two intents, because the read that decided what to write and the write itself were not atomic.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the final state accounts for every concurrent intent, which is what a correct implementation should produce - a compare-and-set, a unique constraint, a serialisable transaction, or an atomic single-key increment. It is also false where the two writes genuinely did not overlap in time, where the endpoint serialises them by design, where the writes target different objects and were never in contention, and where the apparent loss is an artefact of the test harness - a client-side rate limit, a queue that dropped a request while still reporting success, or a caching layer serving a stale read.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://www.postgresql.org/docs/current/transaction-iso.html>
- The damaging form of a race is proven when an invariant that admits exactly one winner - a single remaining seat, one discount per order, one balance to spend - is satisfied twice by concurrent requests, because the response bodies show two winners and the persisted state shows the duplicated spend.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when only one of the concurrent requests is granted the resource and the others receive an explicit conflict, refusal or retry signal, which is the behaviour a correct allocation must show. It is also false where the duplicated effect is intentional and idempotent - applying the same discount to the same order twice is designed behaviour - where the two responses belong to different users who were each entitled to their own allocation, and where the apparent double-spend is a display-layer artefact such as a cached total rather than a persisted balance.
  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://www.postgresql.org/docs/current/transaction-iso.html>

## Impact framing

- Race impact scales with what the single-use resource gates: money, stock, or a security control - and it is often under-detected.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the raced action caused no money, stock or control bypass and downstream records match normal single-use behaviour, the demonstrated impact is negligible.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>

## Defence bypasses

- Bypass: idempotency keys scoped per session (rather than per operation) allow duplicate application because the uniqueness check is not exclusive across the raced window.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation (session-scoped or not).
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions> · <https://redis.io/docs/latest/develop/using-commands/transactions/>
- Bypass: single-use token consumption flag written after the side effect - replaying the privileged action in parallel before the flag commits wins the race.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
- Single-use tokens whose consumption flag is written after the side effect, or idempotency keys scoped per session instead of per operation, lose the race deterministically.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the second request with the identical key returns the original stored response and only one token.used_at row exists, consumption was atomic and the key is enforced per operation.
  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>

## Chaining opportunities

- Chain: a limit-overrun race chained into a financial or fulfilment effect - oversold stock, duplicated fulfilment, repeated referral credit - converts the bug into a payable finding.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the 20 raced checkouts all charged the undiscounted total and the promo ledger shows a single redemption, the race produced no financial gain and the chain does not hold.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions> · <https://hackerone.com/reports/1717650>
- Chaining a limit-overrun race into a financial or fulfilment effect - oversold stock, duplicated fulfilment, repeated referral credit - is what converts the bug into a payable finding.  _(merged 1 duplicate row(s))_
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


## Hunt procedure

1. Take a single-threaded baseline first, then fire 20-30 parallel identical requests; a difference with no baseline is your own tooling.
2. Put a unique nonce in every request and confirm all 20 returned from the origin with distinct timings, so overlap is proven and not assumed.
3. Prove an INVARIANT broke (two winners, oversold stock, negative balance), not merely that the endpoint answered twice with 200.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/race/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
