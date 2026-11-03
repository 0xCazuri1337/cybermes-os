# session: observe, exercise, confirm

> goal: `Establish, exercise and confirm a session condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for session. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a session condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A session identifier appearing in a URL or response on a non-login, unauthenticated page is not session fixation or session hijack: fixation requires the identifier to survive privilege elevation and remain usable for an authenticated resource, otherwise it...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: ZAP's session-fixation guidance states the two cases explicitly, and only one of them is a vulnerability: on a login URL the attacker can hand the victim a fixed session id and later assume their...

**Requires:** an authorised target with a reachable surface for session, and permission to record responses

**Backed by:** `session.fp_rule.session_id_in_url_on_a_non_login_page_is_tracking_not_takeover`

**This step fails if:** It IS fixation if the identifier still authenticates after login (issue it pre-auth, complete a real login with it, then fetch a page that requires authentication and show 200), or if it is set on a login page and accepted unchanged at privilege elevation. The test is reuse-after-login, not presence in the URL.

### 2. Exercise it against the target and capture the raw request and response: A session cookie missing Secure, HttpOnly or SameSite is not itself an exploitable session defect; the finding only survives when a test demonstrates an attacker-reachable path that actually uses the weakness, such as script on the same origin reading the...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `session.fp_rule.missing_cookie_flags_alone_is_not_exploitable`

**This step fails if:** It becomes exploitable when document.cookie on a same-origin XSS returns the session value and that value replays into an authenticated request, when the app serves any HTTP endpoint that receives the cookie, or when a SameSite=None cookie without Secure is accepted so a cross-site request still carries it. If none of those hold, downgrade the report to hardening.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Session termination is only proven by replaying the pre-logout session value against a protected endpoint after logout and observing that it no longer authenticates; a redirect to a login page in the UI is not evidence that the server-side record was...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `session.technique.prove_session_validity_after_logout_by_replay`

**This step fails if:** The test is invalid if the replayed request was sent from a browser whose own cookie jar the server could read implicitly, if a CDN served a cached authenticated body, or if logout in this deployment is by design client-side only with a short session lifetime you have not accounted for.
