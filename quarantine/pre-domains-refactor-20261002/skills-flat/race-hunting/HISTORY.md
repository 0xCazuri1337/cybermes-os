# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-01 22:49 — 1 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
(initial generation, 2026-10-01)
```

## 2026-10-01 22:50 — 40 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
--- race@current
+++ race@new
@@ -16,12 +16,12 @@
 
 ## Prerequisites (do not start without these)
 
+- A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.
+  - **Disproof:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
 - Checkout endpoints that validate payment and confirm the order as two steps of one request leave the cart mutable inside that window.
   - **Disproof:** If the order row snapshots line items at payment validation, later cart writes never reach the confirmed order and paid total equals shipped total.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
-- A race is exploitable only where state is checked, acted on, then persisted in a separate step, and the limit is app logic rather than a DB constraint.
-  - **Disproof:** If check and write run in one transaction or a UNIQUE index on redemptions rejects the second insert, there is no sub-state and no window.
-  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
 
 ## Recon signals (where to look)
 
@@ -31,15 +31,15 @@
 
 ## Techniques (what to change)
 
+- Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.
+  - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
+- Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter.
+  - **Disproof:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
 - Sequence races - one request type in a burst followed immediately by a second request type - catch multi-endpoint windows that single-endpoint bursts miss.
   - **Disproof:** If only one order in the burst carries the discount and later orders show the full price, the two windows never aligned and no chain occurred.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
-- Fire a fixed 20-30 request parallel burst on one gate rather than a naive two-request race, to absorb server-side jitter.
-  - **Disproof:** If 20 parallel calls return the same outcome count as one sequential call, the requests never overlapped and the window was missed.
-  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
-- Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.
-  - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
-  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-01 22:52 — 25 diff lines
- items: 12 (supported 12), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules, skill

```diff
--- race@current
+++ race@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `business` · CWE — · OWASP —
-> evidence: 12 items, 12 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, fp_rules, chain, skill
+> evidence: 12 items, 12 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: methodology, fp_rules, skill
 
 
 ## Prerequisites (do not start without these)
@@ -74,5 +74,11 @@
   - **Disproof:** If the 20 raced checkouts all charged the undiscounted total and the promo ledger shows a single redemption, the race produced no financial gain and the chain does not hold.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/> · <https://portswigger.net/web-security/race-conditions>
 
+## Rejected before you report
+
+- **Two simultaneous coupon redemptions both succeeded**
+  - Killed by: The sequential baseline produced the identical result, and per-request nonces were distinct, so the requests never overlapped at the origin
+  - Rule: Prove concurrency before claiming a race: single-threaded baseline plus distinct origin timings, otherwise you measured your own tooling
+
 ---
 Full class document: `classes/race.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
```

## 2026-10-01 22:55 — 18 diff lines
- items: 12 (supported 12), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- race@current
+++ race@new
@@ -9,9 +9,13 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `business` · CWE — · OWASP —
+> surface `business` · CWE CWE-367 · OWASP A04:2021
 > evidence: 12 items, 12 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, fp_rules, skill
+> maturity: **researching** — missing: methodology, fp_rules
+
+Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
+
+**Also called:** race condition, toctou, time of check time of use, double spend, concurrent request limit bypass
 
 
 ## Prerequisites (do not start without these)
```

## 2026-10-01 23:46 — 11 diff lines
- items: 12 (supported 12), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- race@current
+++ race@new
@@ -11,7 +11,7 @@
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
 > evidence: 12 items, 12 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, fp_rules
+> maturity: **researching** — missing: fp_rules
 
 Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
 
```

## 2026-10-02 01:36 — 11 diff lines
- items: 12 (supported 12), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- race@current
+++ race@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
 > evidence: 12 items, 12 supported, 1 FP rules, 1 chains
```

## 2026-10-02 10:30 — 23 diff lines
- items: 12 (supported 12), FP rules 3, chains 1, state mature

```diff
--- race@current
+++ race@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
-> evidence: 12 items, 12 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: fp_rules
+> evidence: 12 items, 12 supported, 3 FP rules, 1 chains
+> maturity: **mature**
 
 Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
 
@@ -83,6 +83,9 @@
 - **Two simultaneous coupon redemptions both succeeded**
   - Killed by: The sequential baseline produced the identical result, and per-request nonces were distinct, so the requests never overlapped at the origin
   - Rule: Prove concurrency before claiming a race: single-threaded baseline plus distinct origin timings, otherwise you measured your own tooling
+- **Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.**
+  - Killed by: If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
+  - Rule: Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.
 
 ---
 Full class document: `classes/race.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
```

## 2026-10-02 12:21 — 21 diff lines
- items: 12 (supported 12), FP rules 3, chains 2, state mature

```diff
--- race@current
+++ race@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
-> evidence: 12 items, 12 supported, 3 FP rules, 1 chains
+> evidence: 12 items, 12 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
@@ -87,5 +87,9 @@
   - Killed by: If per-request nonces all come back from the origin with distinct timings, the requests did overlap in the app and the cache theory is dead.
   - Rule: Reject the finding if your requests were serialised by tooling or if you measured a CDN/cache instead of the application.
 
+## Chains to
+
+- `bizlogic` (3 shared chain(s))
+
 ---
 Full class document: `classes/race.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
```

## 2026-10-02 13:38 — 33 diff lines
- items: 15 (supported 15), FP rules 3, chains 2, state mature

```diff
--- race@current
+++ race@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `business` · CWE CWE-367 · OWASP A04:2021
-> evidence: 12 items, 12 supported, 3 FP rules, 2 chains
+> evidence: 15 items, 15 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Server-side state is read and acted upon non-atomically, so concurrent requests observe a check result that another request has already invalidated.
@@ -35,6 +35,15 @@
 
 ## Techniques (what to change)
 
+- Race conditions such as this kind may be employed to gain read or write access to resources which are not normally readable or writable by the user in question.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Race conditions such as this kind may be employed to gain read or write access to resource".
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
+- Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free ( CWE-416 ) in one thread
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: A multi-threaded race condition ( CWE-367 ) allows attackers to cause two threads t".
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
+- chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of prote".
+  - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/logic-flaws>
 - Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins drift.
   - **Disproof:** If 10 concurrent 10-unit debits from 100 leave exactly 0, the debit is atomic (single UPDATE ... SET x = x - 10 WHERE x >= 10) and no lost update occurred.
   - Sources: <https://cwe.mitre.org/data/definitions/367.html> · <https://portswigger.net/web-security/race-conditions>
@@ -92,4 +101,4 @@
 - `bizlogic` (3 shared chain(s))
 
 ---
-Full class document: `classes/race.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
+Full class document: `skills/Web/race/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id race`
```
