# Methodology — Rate limiting and throttling

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class rate_limit --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Missing or ineffective throttling on a security-relevant operation, including the cases where the operation is not reachable at all.

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.**

The mechanism being hunted is a counter whose key does not match the attacker's cost model. The OWASP Authentication Cheat Sheet fixes the counter to the account rather than the source IP address, and RFC 6585 makes the same point normatively by declining to define how the origin server identifies the user: counting per-resource, across the whole server, or among a set of servers are all legal, and the client may be identified by credentials or by a stateful cookie. On the target, the observable is a login or OTP endpoint whose throttling state lives somewhere the tester can vary at will - a proxy header, a cookie, a session id - so the request budget is reset by changing that value rather than by slowing down. Confirm by driving N+1 failures from a fixed identity and then repeating from a fresh identity: if the second identity is accepted immediately, the counter is keyed on something the client controls.

- *Disproof:* Refuted if sending the same number of failures from two distinct source addresses leaves the second identity throttled, or if the server rejects any request carrying a rotated/forged identity header rather than counting it against a fresh budget.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [en.wikipedia.org](https://en.wikipedia.org/wiki/Rate_limiting); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6585)

**A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.**

The negative signal is not an unbounded counter but a counter set higher than the backend can absorb. API4:2023 states that an API is vulnerable if at least one of the listed limits is missing or set inappropriately (e.g. too low/high), and enumerates them: execution timeouts, maximum allocable memory, maximum number of file descriptors, maximum number of processes, maximum upload file size, number of operations per single client request, records per page, and third-party spending limits. Wikipedia describes the consequence of a limit being reached at the protocol layer: the server offloads new requests and does not respond to them, sometimes queueing them, and at peak times the request rate exceeds even the queue capacity so requests have to be thrown away. The hunting move is to raise one limit on the target and then apply a burst that a sane value would have shed.

- *Disproof:* Refuted if a burst far above the documented ceiling is shed at the edge (429 or 503) with no measurable latency growth, no queueing backlog and no growth in server-side memory, CPU or backend call volume.
- *Evidence:* high_confidence — [en.wikipedia.org](https://en.wikipedia.org/wiki/Rate_limiting); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)

**A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.**

The indicator is temporal, not volumetric. ATT&CK's brute-force detection analytics describe high volume of failed logon attempts followed by a successful one from a suspicious user, host, or timeframe, multiple authentication failures for valid or invalid users followed by success from the same IP or user, and password spraying or brute force attempts across a user pool within short time intervals. The Authentication Cheat Sheet makes logging the precondition for seeing any of it, directing that logging and monitoring of authentication functions be enabled to detect attacks and failures. A missing limiter and a missing log produce the same quiet endpoint from the outside, so on the target the check is whether a deliberate low-and-slow failure burst leaves any retrievable trace at all - if the burst is invisible in the application's own logs, the absence of a lockout is not the only finding.

- *Disproof:* Refuted if a controlled burst of failed logins followed by one correct login is retrievable from the target's authentication logs with the user, source and timestamp fields needed to correlate the failures to the success.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1110/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.**

This sub-mechanism has nothing to do with password guessing. CWE-770 defines the weakness as a product that allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated, and API4:2023 names the same gap in the API form: it is common to find APIs that do not limit client interactions or resource consumption, and a crafted request carrying a parameter that controls the number of resources returned identifies it, with the same being valid for batched operations. On the target the probe needs no credentials: send an ordinary authenticated or anonymous request that names a large page size, a deep batch, or a large body, and watch the server's memory, CPU and response time rather than its status code.

- *Disproof:* Refuted if the response to an oversized page-size, batch-depth or payload request is a bounded error (413, a capped record count, or a documented maximum) and repeating the same request produces no growth in server-side resource use.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/770.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)

**An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.**

This is the availability face of throttling. The defensive control and the attack share one trigger: a burst of failed logins. The Authentication Cheat Sheet names the failure mode explicitly - care must be taken to prevent the lockout being used to cause a denial of service by locking out other users' accounts - and names the recovery path an attacker relies on, allowing the forgotten password functionality to log in even if the account is locked out. CWE-770 states the same consequence in the abstract: allocating resources without limits lets an attacker prevent other systems, applications or processes from accessing the same type of resource, and it is easy to consume many resources by rapidly making many requests. On the target, the observation is an unauthenticated endpoint where a handful of wrong passwords produces a response naming the victim account and a duration, and where the legitimate owner is then locked out of their own account.

- *Disproof:* Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/770.html)

**The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.**

RFC 6585 defines 429 Too Many Requests as the status for a client that has sent too many requests in a given amount of time, and requires the response representation to include details explaining the condition while making Retry-After optional but meaningful. HTTP/1.1 defines the neighbouring case: 503 Service Unavailable means the server is currently unable to handle the request due to a temporary overload or scheduled maintenance which will likely be alleviated after some delay, and the server may send a Retry-After header field to suggest how long the client should wait. On the target, the check is a repeated-burst probe reading the status line and headers, not the body: a limiter that keeps returning 200 with a truncated or error-shaped payload is enforcing nothing the client can act on, and a 429 that carries no Retry-After still leaves the client to guess the delay and retry immediately.

- *Disproof:* Refuted if the burst produces 429 with an explanatory body and a Retry-After value, or if the server instead answers 503 with Retry-After, which HTTP/1.1 defines for the same temporary-overload condition.
- *Evidence:* high_confidence — [en.wikipedia.org](https://en.wikipedia.org/wiki/Rate_limiting); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6585)

**Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.**

Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones. CWE-770's architecture-and-design mitigation is to limit the amount of resources that are accessible to unprivileged users, to set per-user limits for resources, and to allow the system administrator to define those limits. The protocol-level half of the same bound is described in HTTP/1.1: 413 Payload Too Large is the server refusing to process a request because the payload is larger than it is willing or able to process, and where the condition is temporary the server should generate a Retry-After header field indicating after what time the client may try again. API4:2023 supplies the concrete parameter list for the same idea - maximum length for strings, maximum number of elements in arrays, and maximum upload file size regardless of whether it is stored locally or in cloud storage. The test is whether the bound is per-user and whether it is enforced before the allocation happens.

- *Disproof:* Refuted if every oversized request is refused with 413 before any allocation, and if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/770.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7231)

**Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.**

Two different counters are being conflated. API4:2023 separates them in its prevention guidance: it asks for a limit on how often a client can interact with the API within a defined timeframe, notes that rate limiting should be fine tuned based on the business needs because some endpoints require stricter policies, and then asks separately to limit or throttle how many times a single client or user can execute a single operation, giving validate an OTP and request password recovery without visiting the one-time URL as the examples. CWE-770 states the coarse form of the same control, tracking the rate of requests received from users and blocking requests that exceed a defined rate threshold, and the Authentication Cheat Sheet gives the credential-side shape: a mechanism that prevents too many attempts at guessing a password, whose controls include a maximum number of attempts, with the lockout duration in some implementations doubling after each failure. The test is per-operation: hold total request volume under the global limit and hammer one operation.

- *Disproof:* Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/770.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the...

Adjacent behaviour that produces the same observable result: Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Throttling a single expensive operation per client is a distinct contr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1110/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

**Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe...

Adjacent behaviour that produces the same observable result: A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1110/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
