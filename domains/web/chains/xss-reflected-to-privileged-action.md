# Reflected XSS on an authenticated surface to privileged in-origin actions

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

Script execution in the victim's own origin inherits every permission the victim holds, so the finding is graded on what the injected script can do, not on the payload's originality. An HttpOnly cookie removes session theft but leaves the higher-value targets -- the anti-CSRF token and the state-changing endpoints it protects -- fully reachable.

## Impact

Any action the victim can perform in that origin, performed as the victim: password and email change, MFA enrolment, and state changes that a CSRF token would otherwise protect. Session replay is an ADDITIONAL outcome, available only where the cookie is not HttpOnly.

## Sequence

### 1. Inject a unique alphanumeric marker at each candidate entry point and diff the immediate response to establish which surfaces reflect, and in which context (HTML body, attribute, script string, URL)

**Why it works:** Reflection is the precondition for everything after it, and the context determines the payload. A surface that never returns the marker is not this class and must be dropped before any time is spent on payloads.

**Backed by:** `xss.signal.unique_alnum_marker_reflected_in_response`

**This step fails if:** The marker is absent from the response, appears only encoded in a form that cannot be decoded back into a live context, or is reflected only after a separate later request.

### 2. Craft the breakout for the confirmed context and confirm execution in a browser, not by pattern-matching the response

**Why it works:** Encoded reflection in the response is not proof of execution; the context decides which characters are load-bearing, and only an observed execution separates a finding from a curiosity.

**Backed by:** `xss.technique.html_attribute.break_out_and_add_event_handler`

**This step fails if:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.

### 3. Establish whether the reflecting surface is reachable while the victim is authenticated and what same-origin privileged endpoints the origin exposes

**Why it works:** Impact is priced by the victim's session, not by the payload. An authenticated surface makes the finding materially higher severity because the injected script inherits privileged in-origin actions.

**Requires:** an authenticated account on the target

**Backed by:** `xss.impact.authenticated_reflected_beats_anonymous_page`

**This step fails if:** The vulnerable endpoint is reachable and exploitable only while unauthenticated, and no authenticated page on the same origin reflects the same parameter.

### 4. Read the session cookie's HttpOnly flag, then restate the impact WITHOUT session theft and prove a same-origin privileged action instead

**Why it works:** Reporting cookie exfiltration on an HttpOnly session is the single most common XSS over-claim, and it gets the whole report discounted. The reachable anti-CSRF token and the endpoints behind it survive HttpOnly entirely.

**Backed by:** `xss.validation.httponly_blocks_cookie_theft_chain`

**This step fails if:** The session cookie lacks HttpOnly and document.cookie returns it inside the injected script, so full session replay is achievable.

### 5. Have the injected script read the page's anti-CSRF token and replay the protected state-changing request with it

**Why it works:** CSRF defends against a hostile ORIGIN, not against script running inside the trusted one. Reading the token converts a control the programmer believes is active into a value the attacker's script already holds.

**Requires:** an authenticated victim with a CSRF-protected action available

**Backed by:** `xss.chain_link.csrf_token_read_defeats_csrf_defence`

**This step fails if:** If the state-changing request is refused with a token-validation error even when the script supplies the token read from the same page, the defence is holding and this chain link does not apply to that endpoint.
