# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 05:00 — 1 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
(initial generation, 2026-10-03)
```

## 2026-10-04 00:43 — 74 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -18,42 +18,57 @@
 
 ## Recon signals (where to look)
 
-- A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.
+- A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if sending the same number of failures from two distinct source addresses leaves the second identity throttled, or if the server rejects any request carrying a rotated/forged identity header rather than counting it against a fresh budget.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585>
-- A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.
+- A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if a controlled burst of failed logins followed by one correct login is retrievable from the target's authentication logs with the user, source and timestamp fields needed to correlate the failures to the success.
+  - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a burst far above the documented ceiling is shed at the edge (429 or 503) with no measurable latency growth, no queueing backlog and no growth in server-side memory, CPU or backend call volume.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://en.wikipedia.org/wiki/Rate_limiting>
-- A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.
-  - **Disproof:** Refuted if a controlled burst of failed logins followed by one correct login is retrievable from the target's authentication logs with the user, source and timestamp fields needed to correlate the failures to the success.
-  - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
 ## Techniques (what to change)
 
-- A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.
+- A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the response to an oversized page-size, batch-depth or payload request is a bounded error (413, a capped record count, or a documented maximum) and repeating the same request produces no growth in server-side resource use.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>
-- Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.
+- An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
+  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if every oversized request is refused with 413 before any allocation, and if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://www.rfc-editor.org/rfc/rfc7231>
-- The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.
+- The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the burst produces 429 with an explanatory body and a Retry-After value, or if the server instead answers 503 with Retry-After, which HTTP/1.1 defines for the same temporary-overload condition.
   - Sources: <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585> · <https://www.rfc-editor.org/rfc/rfc7231>
-- Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.
+- Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.
-  - **Disproof:** Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
-  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
-- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Throttling a single expensive operation per client is a distinct contr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/rate_limit/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rate_limit`
```

## 2026-10-04 00:50 — 16 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -58,10 +58,9 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Establish a clean baseline of the allowed rate, then exceed it and measure the window: 429, a silent queue, or a captcha that never appears.
+2. Test whether the limit keys on IP only -- rotate the source address or add an X-Forwarded-For the backend trusts.
+3. For a single-use resource, fire PARALLEL requests; a sequential loop proves nothing about an atomic limit.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -71,6 +71,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/rate_limit/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rate_limit`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 22:01 — 36 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE — · OWASP —
-> evidence: 10 items, 10 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 Missing or ineffective throttling on a security-relevant operation, including the cases where the operation is not reachable at all.
 
@@ -30,6 +30,9 @@
 
 ## Techniques (what to change)
 
+- A limiter whose counter is held per replica enforces the full configured allowance independently on every backend, so one client that spreads its requests across N replicas spends that allowance N times and the real ceiling is the documented limit multiplied by the replica count while every individual replica's counter still reads as correct.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the same client is refused after N successes in total once its requests are spread across all replicas, or if the counter is read and written in a shared store that every replica consults so the enforced total is fleet-wide, or if a consistent-hashing load balancer already pins the client to one replica and the measured aggregate then equals N, or if adding replicas leaves the measured aggregate cut-off unchanged. Failing to observe the multiplier is not refutation when the limiter silently fell back to local counters, which must be ruled out separately by confirming the shared store is reachable.
+  - Sources: <https://developer.konghq.com/plugins/rate-limiting> · <https://developer.konghq.com/plugins/rate-limiting-advanced> · <https://learn.microsoft.com/en-us/azure/api-management/rate-limit-policy>
 - A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the response to an oversized page-size, batch-depth or payload request is a bounded error (413, a capped record count, or a documented maximum) and repeating the same request produces no growth in server-side resource use.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>
@@ -45,6 +48,12 @@
 - Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+
+## Tests
+
+- A rate limiter built on a fixed-window counter zeroes its tally when the window rolls rather than carrying it forward, so a client that spends its full allowance in the last seconds of one window and again in the first seconds of the next delivers close to twice the documented per-period allowance inside a fraction of the period, and no single window ever exceeds the ceiling.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the straddling burst is refused at exactly the count a mid-window burst of the same size is refused, or if a remaining-quota or reset indicator on the endpoint response never returns to full at any boundary and instead decays continuously across it, or if the limiter's state survives the boundary as a token bucket or a sliding-window log. A token bucket whose burst capacity is at least N also passes a 2N burst, so the disproof is the refill behaviour across the boundary, not the refusal count.
+  - Sources: <https://learn.microsoft.com/en-us/azure/architecture/patterns/throttling> · <https://redis.io/tutorials/howtos/ratelimiting> · <https://upstash.com/docs/redis/sdks/ratelimit-py/algorithms>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-28 21:43 — 71 diff lines
- items: 20 (supported 19), FP rules 2, chains 1, state mature

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE — · OWASP —
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 20 items, 19 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Missing or ineffective throttling on a security-relevant operation, including the cases where the operation is not reachable at all.
@@ -30,12 +30,21 @@
 
 ## Techniques (what to change)
 
+- A fixed-window counter zeroes its tally at the boundary, so a client that spends its full allowance in the last seconds of one window and the first seconds of the next gets nearly twice the documented per-period allowance.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the straddling burst is refused at exactly the count a mid-window burst of the same size is refused, or the remaining-quota header never returns to full at any boundary and instead decays continuously, or the limiter's state survives the boundary as a token bucket or sliding-window log.
+  - Sources: <https://learn.microsoft.com/en-us/azure/architecture/patterns/throttling> · <https://redis.io/tutorials/howtos/ratelimiting> · <https://upstash.com/docs/redis/sdks/ratelimit-py/algorithms>
 - A limiter whose counter is held per replica enforces the full configured allowance independently on every backend, so one client that spreads its requests across N replicas spends that allowance N times and the real ceiling is the documented limit multiplied by the replica count while every individual replica's counter still reads as correct.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the same client is refused after N successes in total once its requests are spread across all replicas, or if the counter is read and written in a shared store that every replica consults so the enforced total is fleet-wide, or if a consistent-hashing load balancer already pins the client to one replica and the measured aggregate then equals N, or if adding replicas leaves the measured aggregate cut-off unchanged. Failing to observe the multiplier is not refutation when the limiter silently fell back to local counters, which must be ruled out separately by confirming the shared store is reachable.
+  - Sources: <https://developer.konghq.com/plugins/rate-limiting> · <https://developer.konghq.com/plugins/rate-limiting-advanced> · <https://learn.microsoft.com/en-us/azure/api-management/rate-limit-policy>
+- A per-replica counter enforces the full allowance independently on every backend, so the real ceiling is the documented limit multiplied by the replica count while every individual replica's counter still reads as correct.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the same client is refused after N successes in total once its requests are spread across all replicas, or if the counter is read and written in a shared store every replica consults so the enforced total is fleet-wide, or if a consistent-hashing load balancer already pins the client to one replica and the measured aggregate then equals N, or if adding replicas leaves the measured aggregate cut-off unchanged. Failing to observe the multiplier is not refutation when the limiter silently fell back to local counters, which must be ruled out by confirming the shared store is reachable.
   - Sources: <https://developer.konghq.com/plugins/rate-limiting> · <https://developer.konghq.com/plugins/rate-limiting-advanced> · <https://learn.microsoft.com/en-us/azure/api-management/rate-limit-policy>
 - A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the response to an oversized page-size, batch-depth or payload request is a bounded error (413, a capped record count, or a documented maximum) and repeating the same request produces no growth in server-side resource use.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>
+- An account lockout that disables the account after a low failure threshold converts password guessing into a denial of service reachable by anyone who knows the username.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
+  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
@@ -45,6 +54,9 @@
 - The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the burst produces 429 with an explanatory body and a Retry-After value, or if the server instead answers 503 with Retry-After, which HTTP/1.1 defines for the same temporary-overload condition.
   - Sources: <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585> · <https://www.rfc-editor.org/rfc/rfc7231>
+- Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so OTP and password-recovery endpoints stay abusable when only a global per-timeframe limit is present.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
+  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
   - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
@@ -63,6 +75,27 @@
 - Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+
+## Impact framing
+
+- Missing throttling on a security-relevant operation is unbounded resource consumption (CWE-770) exploitable with plain repeated requests, and a limit set too generously does not fail closed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if every oversized request is refused with 413 before any allocation and repeating the same request produces no growth in server-side resource use, or if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.
+  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://www.rfc-editor.org/rfc/rfc7231>
+
+## Defence bypasses
+
+- Batching or parameter pollution compresses many logical operations into one physical request, bypassing per-request and per-operation rate limits.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The bypass fails when each logical operation carries its own per-operation counter, when the batch endpoint is itself subject to the same global throttle, or when the server detects and rejects oversized batches before applying the per-operation limit.
+  - Sources: <https://github.com/aj-omanai/1st/blob/main/anthropic-cybersecurity-skills/skills/performing-api-rate-limiting-bypass/SKILL.md> · <https://github.com/aw-junaid/bug-bounty/blob/main/resources/cheatsheets/API%20Security.md> · <https://havbay.gitbook.io/0xhavbay/web-security/http-attacks/parameter-pollution>
+- Rate limiting keyed on source IP is bypassable by proxy rotation or spoofed, client-controlled headers so the attacker never trips a single counter.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The bypass fails when the limiter keys on account or session rather than IP alone, validates or ignores forwarded headers, or combines the header with a session-bound counter so the header is only one factor in the key.
+  - Sources: <https://cyber-security.wiki/docs/application-security/Web-Rate-Limiting/> · <https://github.com/aw-junaid/bug-bounty/blob/main/resources/cheatsheets/API%20Security.md> · <https://havbay.gitbook.io/0xhavbay/web-security/http-attacks/parameter-pollution>
+
+## Chaining opportunities
+
+- Missing or bypassable rate limiting on credential endpoints converts into credential stuffing, password spraying and account takeover chains.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The chain is broken if the endpoint enforces an account-bound throttle keyed to the account rather than the IP, and the lockout and recovery path itself is protected, so spraying leaves a loggable signature and the legitimate owner retains recovery.
+  - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://cyber-security.wiki/docs/application-security/Web-Rate-Limiting/>
 
 
 ## Hunt procedure
```

## 2026-10-31 06:41 — 35 diff lines
- items: 20 (supported 16), FP rules 0, chains 1, state researching
- still missing: fp_rules

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE — · OWASP —
-> evidence: 20 items, 19 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 20 items, 16 supported, 0 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 Missing or ineffective throttling on a security-relevant operation, including the cases where the operation is not reachable at all.
 
@@ -21,7 +21,7 @@
 - A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if sending the same number of failures from two distinct source addresses leaves the second identity throttled, or if the server rejects any request carrying a rotated/forged identity header rather than counting it against a fresh budget.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585>
-- A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.  _(merged 1 duplicate row(s))_
+- A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted if a controlled burst of failed logins followed by one correct login is retrievable from the target's authentication logs with the user, source and timestamp fields needed to correlate the failures to the success.
   - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.  _(merged 1 duplicate row(s))_
@@ -69,10 +69,10 @@
 
 ## False-positive rules (when to reject it)
 
-- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Throttling a single expensive operation per client is a distinct contr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 20 (supported 16), FP rules 0, chains 1, state researching
- still missing: fp_rules

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -112,7 +112,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/web/rate_limit/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rate_limit`
+Full class document: `skills/web/rate_limit/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rate_limit`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 20 (supported 16), FP rules 0, chains 1, state researching
- still missing: fp_rules

```diff
--- rate_limit@current
+++ rate_limit@new
@@ -5,7 +5,8 @@
 
 # Rate limiting and throttling — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
