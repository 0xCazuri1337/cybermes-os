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
