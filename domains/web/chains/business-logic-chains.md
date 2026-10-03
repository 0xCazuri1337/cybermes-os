# Single-use entitlement limit overrun to quantified settlement over-issue

## Objective

Goal: **financial_loss**.

A check-then-act window on a single-use entitlement becomes a payable finding only once the duplicated effect is quantified at settlement rather than demonstrated as a duplicated response.

## Preconditions

Not yet researched.

## Initial Weakness

**Step 1.** Run the sequential two-request baseline first and record whether the second sequential redemption is rejected.

- Why: Without the sequential control a duplicated result cannot be attributed to concurrency; it may be your own connection pool serialising the burst, which is the standard false positive here.

## Chain Steps

**1. `bizlogic` — Run the sequential two-request baseline first and record whether the second sequential redemption is rejected.**

- Why: Without the sequential control a duplicated result cannot be attributed to concurrency; it may be your own connection pool serialising the burst, which is the standard false positive here.

**2. `race` — Locate the check-then-act window itself - the check, the applied effect, and the record update - that a concurrent pair can interleave across.**

- Why: The window between checking the single-use record and writing the updated record is the whole primitive; a single-use endpoint with no such window cannot be overrun.

**3. `race` — Issue a parallel burst at the single-use endpoint sized to overlap the window, then read the used counter back from an independent session.**

- Why: Issuing multiple requests in quick succession to see whether the limit can be overrun is the documented procedure, and reading the counter from another session avoids trusting the response body of the raced request itself.

**4. `race` — Scale the burst to a quantified number and compute the realised over-issue - discount dollars, item count, or credit balance - at settlement.**

- Why: The reportable figure is the money that actually moved, not the trace; a database uniqueness constraint rather than session state is the control whose absence let the burst succeed.

## Required Conditions

Not yet researched.

## Impact

Direct financial loss - discount dollars over-issued, limited stock oversold, or referral credit minted without the qualifying spend.

## Detection Strategy

Not yet researched.

## Validation

Not yet researched.

## Real-World Examples

Not yet researched.

## Related Bug Classes

- `bizlogic` — canonical: [`skills/Web/bizlogic/CLASS.md`]
- `race` — canonical: [`skills/Web/race/CLASS.md`]

## References

- **cwe.mitre.org** — <https://cwe.mitre.org/data/definitions/367.html>
- **httpwg.org** — <https://httpwg.org/specs/rfc9110.html>
- **owasp.org** — <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>
- **portswigger.net** — <https://portswigger.net/web-security/race-conditions>
- **projectdiscovery.io** — <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
