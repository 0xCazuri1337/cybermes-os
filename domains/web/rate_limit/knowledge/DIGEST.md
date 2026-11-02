# Rate limiting and throttling

> surface: `identity` · CWE: — · OWASP: —
> maturity: **researching** — 20 items, 16 supported, 0 FP rules, 1 chains

Missing or ineffective throttling on a security-relevant operation, including the cases where the operation is not reachable at all.

## Signal

- **A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.**  
  `high_confidence` · score 0.9185 · disproved by: Refuted if sending the same number of failures from two distinct source addresses leaves the second identity throttled, or if the server rejects any request carrying a rotated/forged identity header rather than counting it against a fresh budget.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585>
- **A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.**  
  `high_confidence` · score 0.8415 · disproved by: Refuted if a burst far above the documented ceiling is shed at the edge (429 or 503) with no measurable latency growth, no queueing backlog and no growth in server-side memory, CPU or backend call volume.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://en.wikipedia.org/wiki/Rate_limiting>
- **A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.**  
  `under_review` · score 0.8415 · disproved by: Refuted if a controlled burst of failed logins followed by one correct login is retrievable from the target's authentication logs with the user, source and timestamp fields needed to correlate the failures to the success.
  sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Technique

- **A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.**  
  `high_confidence` · score 0.952 · disproved by: Refuted if the response to an oversized page-size, batch-depth or payload request is a bounded error (413, a capped record count, or a documented maximum) and repeating the same request produces no growth in server-side resource use.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>
- **A limiter whose counter is held per replica enforces the full configured allowance independently on every backend, so one client that spreads its requests across N replicas spends that allowance N times and the real ceiling is the documented limit multiplied by the replica count while every individual replica's counter still reads as correct.**  
  `high_confidence` · score 0.946 · disproved by: Refuted if the same client is refused after N successes in total once its requests are spread across all replicas, or if the counter is read and written in a shared store that every replica consults so the enforced total is fleet-wide, or if a consistent-hashing load balancer already pins the client to one replica and the measured aggregate then equals N, or if adding replicas leaves the measured aggregate cut-off unchanged. Failing to observe the multiplier is not refutation when the limiter silently fell back to local counters, which must be ruled out separately by confirming the shared store is reachable.
  sources: <https://developer.konghq.com/plugins/rate-limiting> · <https://developer.konghq.com/plugins/rate-limiting-advanced> · <https://learn.microsoft.com/en-us/azure/api-management/rate-limit-policy> · <https://learn.microsoft.com/en-us/azure/architecture/patterns/throttling>
- **An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.**  
  `high_confidence` · score 0.9325 · disproved by: Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.**  
  `high_confidence` · score 0.91 · disproved by: Refuted if the burst produces 429 with an explanatory body and a Retry-After value, or if the server instead answers 503 with Retry-After, which HTTP/1.1 defines for the same temporary-overload condition.
  sources: <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585> · <https://www.rfc-editor.org/rfc/rfc7231>
- **Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.**  
  `high_confidence` · score 0.888 · disproved by: Refuted if every oversized request is refused with 413 before any allocation, and if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://www.rfc-editor.org/rfc/rfc7231>
- **Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so OTP and password-recovery endpoints stay abusable when only a global per-timeframe limit is present.**  
  `high_confidence` · score 0.885 · disproved by: Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.**  
  `high_confidence` · score 0.885 · disproved by: Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **A per-replica counter enforces the full allowance independently on every backend, so the real ceiling is the documented limit multiplied by the replica count while every individual replica's counter still reads as correct.**  
  `high_confidence` · score 0.8825 · disproved by: Refuted if the same client is refused after N successes in total once its requests are spread across all replicas, or if the counter is read and written in a shared store every replica consults so the enforced total is fleet-wide, or if a consistent-hashing load balancer already pins the client to one replica and the measured aggregate then equals N, or if adding replicas leaves the measured aggregate cut-off unchanged. Failing to observe the multiplier is not refutation when the limiter silently fell back to local counters, which must be ruled out by confirming the shared store is reachable.
  sources: <https://developer.konghq.com/plugins/rate-limiting> · <https://developer.konghq.com/plugins/rate-limiting-advanced> · <https://learn.microsoft.com/en-us/azure/api-management/rate-limit-policy> · <https://learn.microsoft.com/en-us/azure/architecture/patterns/throttling>
- **An account lockout that disables the account after a low failure threshold converts password guessing into a denial of service reachable by anyone who knows the username.**  
  `high_confidence` · score 0.833 · disproved by: Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **A fixed-window counter zeroes its tally at the boundary, so a client that spends its full allowance in the last seconds of one window and the first seconds of the next gets nearly twice the documented per-period allowance.**  
  `high_confidence` · score 0.8275 · disproved by: Refuted if the straddling burst is refused at exactly the count a mid-window burst of the same size is refused, or the remaining-quota header never returns to full at any boundary and instead decays continuously, or the limiter's state survives the boundary as a token bucket or sliding-window log.
  sources: <https://learn.microsoft.com/en-us/azure/architecture/patterns/throttling> · <https://redis.io/tutorials/howtos/ratelimiting> · <https://upstash.com/docs/redis/sdks/ratelimit-py/algorithms>

## Test

- **A rate limiter built on a fixed-window counter zeroes its tally when the window rolls rather than carrying it forward, so a client that spends its full allowance in the last seconds of one window and again in the first seconds of the next delivers close to twice the documented per-period allowance inside a fraction of the period, and no single window ever exceeds the ceiling.**  
  `high_confidence` · score 0.946 · disproved by: Refuted if the straddling burst is refused at exactly the count a mid-window burst of the same size is refused, or if a remaining-quota or reset indicator on the endpoint response never returns to full at any boundary and instead decays continuously across it, or if the limiter's state survives the boundary as a token bucket or a sliding-window log. A token bucket whose burst capacity is at least N also passes a 2N burst, so the disproof is the refill behaviour across the boundary, not the refusal count.
  sources: <https://learn.microsoft.com/en-us/azure/architecture/patterns/throttling> · <https://redis.io/tutorials/howtos/ratelimiting> · <https://upstash.com/docs/redis/sdks/ratelimit-py/algorithms>

## Fp Rule

- **Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.8965 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Throttling a single expensive operation per client is a distinct contr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.8965 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Impact

- **Missing throttling on a security-relevant operation is unbounded resource consumption (CWE-770) exploitable with plain repeated requests, and a limit set too generously does not fail closed.**  
  `high_confidence` · score 0.924 · disproved by: Refuted if every oversized request is refused with 413 before any allocation and repeating the same request produces no growth in server-side resource use, or if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.
  sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://www.rfc-editor.org/rfc/rfc7231>

## Bypass

- **Batching or parameter pollution compresses many logical operations into one physical request, bypassing per-request and per-operation rate limits.**  
  `under_review` · score 0.8815 · disproved by: The bypass fails when each logical operation carries its own per-operation counter, when the batch endpoint is itself subject to the same global throttle, or when the server detects and rejects oversized batches before applying the per-operation limit.
  sources: <https://github.com/aj-omanai/1st/blob/main/anthropic-cybersecurity-skills/skills/performing-api-rate-limiting-bypass/SKILL.md> · <https://github.com/aw-junaid/bug-bounty/blob/main/resources/cheatsheets/API%20Security.md> · <https://havbay.gitbook.io/0xhavbay/web-security/http-attacks/parameter-pollution>
- **Rate limiting keyed on source IP is bypassable by proxy rotation or spoofed, client-controlled headers so the attacker never trips a single counter.**  
  `high_confidence` · score 0.854 · disproved by: The bypass fails when the limiter keys on account or session rather than IP alone, validates or ignores forwarded headers, or combines the header with a session-bound counter so the header is only one factor in the key.
  sources: <https://cyber-security.wiki/docs/application-security/Web-Rate-Limiting/> · <https://github.com/aw-junaid/bug-bounty/blob/main/resources/cheatsheets/API%20Security.md> · <https://havbay.gitbook.io/0xhavbay/web-security/http-attacks/parameter-pollution>

## Chain Link

- **Missing or bypassable rate limiting on credential endpoints converts into credential stuffing, password spraying and account takeover chains.**  
  `high_confidence` · score 0.9175 · disproved by: The chain is broken if the endpoint enforces an account-bound throttle keyed to the account rather than the IP, and the lockout and recovery path itself is protected, so spraying leaves a loggable signature and the legitimate owner retains recovery.
  sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://cyber-security.wiki/docs/application-security/Web-Rate-Limiting/>

## Known gaps

Not yet satisfied: `fp_rules`
