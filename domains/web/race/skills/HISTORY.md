# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 15 (supported 15), FP rules 3, chains 2, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 15 (supported 15), FP rules 3, chains 2, state mature

```diff
--- race@current
+++ race@new
@@ -101,4 +101,4 @@
 - `bizlogic` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/race/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
+Full class document: `domains/web/race/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
```

## 2026-10-02 19:37 — 41 diff lines
- items: 16 (supported 13), FP rules 3, chains 2, state mature

```diff
--- race@current
+++ race@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
-> evidence: 15 items, 15 supported, 3 FP rules, 2 chains
+> evidence: 16 items, 13 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
@@ -35,13 +35,13 @@
 
 ## Techniques (what to change)
 
-- Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question.
+- Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Race conditions such as this kind may be employed to gain read or write access to resource".
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
-- Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread
+- Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads t".
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
-- chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.
+- chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of prote".
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
 - Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.
@@ -53,6 +53,12 @@
 - Sequence races - one request type in a burst followed immediately by a second request type - catch multi-endpoint windows that single-endpoint bursts miss.
   - **Disproof:** If only one order in the burst carries the discount and later orders show the full price, the two windows never aligned and no chain occurred.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
+
+## Tests
+
+- To decide this case, observe: . Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (race.fp.verify_concurrency_reached_origin) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 59 diff lines
- items: 20 (supported 17), FP rules 3, chains 2, state mature

```diff
--- race@current
+++ race@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
-> evidence: 16 items, 13 supported, 3 FP rules, 2 chains
+> evidence: 20 items, 17 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
@@ -37,13 +37,13 @@
 
 - Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Race conditions such as this kind may be employed to gain read or write access to resource".
-  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html>
 - Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads t".
-  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html>
 - chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of prote".
-  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html>
 - Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.
   - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
@@ -56,7 +56,7 @@
 
 ## Tests
 
-- To decide this case, observe: . Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.
+- To decide this case, observe: Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (race.fp.verify_concurrency_reached_origin) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>
 
@@ -74,6 +74,21 @@
 - Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.
   - **Disproof:** If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>
+
+## Evidence requirements
+
+- The damaging form of a race is proven when an invariant that admits exactly one winner - a single remaining seat, one discount per order, one balance to spend - is satisfied twice by concurrent requests, because the response bodies show two winners and the persisted state shows the duplicated spend.
+  - **Disproof:** The claim is false when only one of the concurrent requests is granted the resource and the others receive an explicit conflict, refusal or retry signal, which is the behaviour a correct allocation must show. It is also false where the duplicated effect is intentional and idempotent - applying the same discount to the same order twice is designed behaviour - where the two responses belong to different users who were each entitled to their own allocation, and where the apparent double-spend is a display-layer artefact such as a cached total rather than a persisted balance.
+  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://www.postgresql.org/docs/current/transaction-iso.html>
+- A concurrent attempt that is deliberately aborted is the disproof of the finding: when one of two simultaneous writes is rejected because the value it read had changed, the endpoint enforced its invariant atomically and the race does not exist.
+  - **Disproof:** The disproof is void - the race stands - when both writes are applied despite the second having observed a changed value, which means the check was not enforced; when the abort is only advisory and the caller proceeds on a stale read anyway; when the comparison key is unrelated to the value actually written, so nothing that mattered was watched; and when the two requests were never concurrent in the relevant sense, one having fully completed and committed before the other read.
+  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://sqlite.org/isolation.html>
+- A race condition is proven when two requests issued concurrently against the same object both return success but the final state reflects only one of the two intents, because the read that decided what to write and the write itself were not atomic.
+  - **Disproof:** The claim is false when the final state accounts for every concurrent intent, which is what a correct implementation should produce - a compare-and-set, a unique constraint, a serialisable transaction, or an atomic single-key increment. It is also false where the two writes genuinely did not overlap in time, where the endpoint serialises them by design, where the writes target different objects and were never in contention, and where the apparent loss is an artefact of the test harness - a client-side rate limit, a queue that dropped a request while still reporting success, or a caching layer serving a stale read.
+  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://redis.io/docs/latest/develop/using-commands/transactions/> · <https://www.postgresql.org/docs/current/transaction-iso.html>
+- A check-then-act sequence - validate a permission, a price, a state flag or a balance, then act on the value that check returned - is proven exploitable when acting on the earlier value succeeds after the check, because the artifact is a state transition that the check that was supposed to authorise it no longer describes.
+  - **Disproof:** The claim is false when the act re-reads and re-validates rather than using the earlier value, so a change between check and act causes refusal instead of success; when the pair is genuinely atomic at the storage layer, as a compare-and-swap or a conditional write; when the resource being acted on is not attacker-influenceable between the two operations; and when the observed transition is one the endpoint is entitled to perform regardless of the check's outcome, in which case the check was advisory and no invariant was violated.
+  - Sources: <https://cwe.mitre.org/data/definitions/362.html> · <https://cwe.mitre.org/data/definitions/370.html> · <https://www.postgresql.org/docs/current/transaction-iso.html>
 
 ## Impact framing
 
```
