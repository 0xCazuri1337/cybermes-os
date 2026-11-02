# Reflected XSS on an authenticated surface to privileged in-origin actions

## Objective

Goal: **account_takeover**.

Script execution in the victim's own origin inherits every permission the victim holds, so the finding is graded on what the injected script can do, not on the payload's originality. An HttpOnly cookie removes session theft but leaves the higher-value targets -- the anti-CSRF token and the state-changing endpoints it protects -- fully reachable.

## Preconditions

3. an authenticated account on the target
5. an authenticated victim with a CSRF-protected action available

## Initial Weakness

**Step 1.** Inject a unique alphanumeric marker at each candidate entry point and diff the immediate response to establish which surfaces reflect, and in which context (HTML body, attribute, script string, URL)

- Why: Reflection is the precondition for everything after it, and the context determines the payload. A surface that never returns the marker is not this class and must be dropped before any time is spent on payloads.

## Chain Steps

**1. `xss` — Inject a unique alphanumeric marker at each candidate entry point and diff the immediate response to establish which surfaces reflect, and in which context (HTML body, attribute, script string, URL)**

- Why: Reflection is the precondition for everything after it, and the context determines the payload. A surface that never returns the marker is not this class and must be dropped before any time is spent on payloads.

**2. `xss` — Craft the breakout for the confirmed context and confirm execution in a browser, not by pattern-matching the response**

- Why: Encoded reflection in the response is not proof of execution; the context decides which characters are load-bearing, and only an observed execution separates a finding from a curiosity.

**3. `xss` — Establish whether the reflecting surface is reachable while the victim is authenticated and what same-origin privileged endpoints the origin exposes**

- Why: Impact is priced by the victim's session, not by the payload. An authenticated surface makes the finding materially higher severity because the injected script inherits privileged in-origin actions.
- Requires: an authenticated account on the target

**4. `xss` — Read the session cookie's HttpOnly flag, then restate the impact WITHOUT session theft and prove a same-origin privileged action instead**

- Why: Reporting cookie exfiltration on an HttpOnly session is the single most common XSS over-claim, and it gets the whole report discounted. The reachable anti-CSRF token and the endpoints behind it survive HttpOnly entirely.

**5. `xss` — Have the injected script read the page's anti-CSRF token and replay the protected state-changing request with it**

- Why: CSRF defends against a hostile ORIGIN, not against script running inside the trusted one. Reading the token converts a control the programmer believes is active into a value the attacker's script already holds.
- Requires: an authenticated victim with a CSRF-protected action available

## Required Conditions

- an authenticated account on the target
- an authenticated victim with a CSRF-protected action available

## Impact

Any action the victim can perform in that origin, performed as the victim: password and email change, MFA enrolment, and state changes that a CSRF token would otherwise protect. Session replay is an ADDITIONAL outcome, available only where the cookie is not HttpOnly.

## Detection Strategy

Not yet researched.

## Validation

Not yet researched.

## Real-World Examples

Not yet researched.

## Related Bug Classes

- `xss` — canonical: [`web/xss/xss.md`](../bug-classes/web/xss/xss.md)

## References

- **cheatsheetseries.owasp.org** — <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- **cheatsheetseries.owasp.org** — <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- **cheatsheetseries.owasp.org** — <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
- **owasp.org** — <https://owasp.org/www-community/attacks/xss/>
- **portswigger.net** — <https://portswigger.net/web-security/cross-site-scripting>
- **portswigger.net** — <https://portswigger.net/web-security/cross-site-scripting/contexts>
- **portswigger.net** — <https://portswigger.net/web-security/cross-site-scripting/exploiting>
- **portswigger.net** — <https://portswigger.net/web-security/cross-site-scripting/reflected>
