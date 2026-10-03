---
name: rate_limit-hunting
description: Use when hunting Rate limiting and throttling in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Rate limiting and throttling — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE — · OWASP —
> evidence: 10 items, 10 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

Missing or ineffective throttling on a security-relevant operation, including the cases where the operation is not reachable at all.


## Recon signals (where to look)

- A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.
  - **Disproof:** Refuted if sending the same number of failures from two distinct source addresses leaves the second identity throttled, or if the server rejects any request carrying a rotated/forged identity header rather than counting it against a fresh budget.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585>
- A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.
  - **Disproof:** Refuted if a burst far above the documented ceiling is shed at the edge (429 or 503) with no measurable latency growth, no queueing backlog and no growth in server-side memory, CPU or backend call volume.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://en.wikipedia.org/wiki/Rate_limiting>
- A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.
  - **Disproof:** Refuted if a controlled burst of failed logins followed by one correct login is retrievable from the target's authentication logs with the user, source and timestamp fields needed to correlate the failures to the success.
  - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Techniques (what to change)

- A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.
  - **Disproof:** Refuted if the response to an oversized page-size, batch-depth or payload request is a bounded error (413, a capped record count, or a documented maximum) and repeating the same request produces no growth in server-side resource use.
  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>
- Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.
  - **Disproof:** Refuted if every oversized request is refused with 413 before any allocation, and if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.
  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://www.rfc-editor.org/rfc/rfc7231>
- The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.
  - **Disproof:** Refuted if the burst produces 429 with an explanatory body and a Retry-After value, or if the server instead answers 503 with Retry-After, which HTTP/1.1 defines for the same temporary-overload condition.
  - Sources: <https://en.wikipedia.org/wiki/Rate_limiting> · <https://www.rfc-editor.org/rfc/rfc6585> · <https://www.rfc-editor.org/rfc/rfc7231>
- Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.
  - **Disproof:** Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.
  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.
  - **Disproof:** Refuted if the lockout is applied per source address rather than per account, or if the response never confirms that a named account has been locked, or if a working recovery path remains available to the account owner for the whole lockout period.
  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## False-positive rules (when to reject it)

- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the..." and "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Throttling a single expensive operation per client is a distinct contr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe..." and "A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://attack.mitre.org/techniques/T1110/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

---
Full class document: `domains/web/rate_limit/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rate_limit`
