<!-- GENERATED from db/wks.db — do not edit -->
# Cross-Site Request Forgery

## Definition

A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.

- **CWE:** CWE-352
- **OWASP:** A01:2021
- **Surface:** web
- **Aliases:** ["csrf", "cross site request forgery", "xsrf", "csrf token bypass"]

Canonical home for `csrf`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.**

A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.

HackTricks reference: csrf (https://kathan19.gitbook.io/howtohunt/csrf/csrf.md)

*Disproof:* If every request reachable at the endpoint is read-only and produces no state change for the victim, the cross-site request forgery claim is refuted.

**A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.**

A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.

HackTricks reference: csrf (https://kathan19.gitbook.io/howtohunt/csrf/csrf.md)

*Disproof:* If every request reachable at the endpoint is read-only and produces no state change for the victim, the cross-site request forgery claim is refuted.

**CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.**

PortSwigger states three conditions must be in place for a CSRF attack to be possible: a relevant action (privileged, such as modifying permissions for other users, or any action on user-specific data such as changing the user's own password); cookie-based session handling, where the application relies solely on session cookies to identify the user and there is no other mechanism for tracking sessions or validating requests; and no unpredictable request parameters, meaning the requests that perform the action contain no parameters whose values the attacker cannot determine or guess. The password-change example makes the third condition concrete: the function is not vulnerable if the attacker needs to know the value of the existing password. Triage use: a state-changing POST protected by a re-typed password fails condition three and is not a CSRF finding, no matter what the cookies do. Testing a CSRF candidate means establishing all three, not one.

*Disproof:* Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A web application that identifies the user only through a session cookie, with no anti-CSRF token, custom request header, or origin check, lets an attacker forge state-changing requests that execute as the victim.**

PortSwigger defines the classic CSRF conditions: (1) a relevant action the attacker has reason to induce; (2) cookie-based session handling with no other session tracking or request validation; (3) no unpredictable request parameters. When a victim visits a crafted page, the browser automatically includes the session cookie (if SameSite does not block it) and the application processes the request as legitimate. Impact ranges from changing email or password to full account takeover when the victim is privileged, because the attacker then operates under the victim's identity for any action the application exposes.

*Disproof:* The state-changing endpoint requires a secret, unpredictable CSRF token per session, issues a custom request header the attacker cannot set cross-origin, verifies Origin or Referer against its own domain, or the session cookie is set with SameSite=Strict and no sibling-subdomain bypass is available.

**A code change deployed on 2022-02-14 disabled the CSRF protection on all Stripe Dashboard endpoints, letting a cross-site form POST change the victim's email subscription settings without a token; the flaw was fixed on 2022-03-03.**

d_sharad reported that the CSRF token validation system was disabled in the Stripe Dashboard. An attacker could trick a victim into visiting a malicious site and cause limited changes to the victim's Stripe account, such as email subscription settings, without a CSRF token. Money movement remained protected by password re-entry and reCAPTCHA. Stripe found no evidence of user impact during the 18-day window; the report had been incorrectly closed during triage, so both reporters were rewarded for a total of $5,000.

*Disproof:* Retain CSRF middleware globally, restrict the disabled actions to non-sensitive operations requiring step-up authentication, or ensure no state-changing action is reachable cross-origin.

**A cross-origin write shaped like an HTML form submission is delivered by the browser with no CORS preflight and no Access-Control-Allow-Origin opt-in from the target, so a 200 on that request is a same-origin action taken on the victim's behalf, not a read the browser blocked.**

The distinction that makes CSRF easy to miss is that CORS governs whether the attacker's script may READ the response, not whether the request is SENT. A form-shaped submission - one of the CORS-allowed methods with an allow-listed Content-Type and no custom header - never triggers the OPTIONS preflight, and the server is not required to opt in before receiving it, because from the browser's point of view the threat is no worse than an ordinary form submission. So a hunter cannot use the browser console as a verdict: a blocked read and a refused write look identical in the UI while meaning opposite things. The artifact is the request log or proxy record of the simple request arriving and being executed, paired with the durable effect; a page that never even emitted the request because of preflight is a negative finding, not a positive one.

*Disproof:* The claim is false when the request is in fact preflighted - a custom header, a non-simple Content-Type such as application/json, or a DELETE - and the server's OPTIONS response withholds the Access-Control-Allow-Origin value, in which case the browser never sends the write and no state change is reachable cross-origin. It is also false when the endpoint validates an anti-CSRF token, a custom header or the Origin value, and false when the durable effect is not attacker-meaningful.

**An endpoint that derives its CSRF decision from the Origin header it receives proves nothing when the header can be made to carry the victim's own origin, because the check and the forgery then agree by construction and the forged request is accepted with a 200 and the state change applied.**

Origin was introduced precisely to carry the scope of authority a user agent assigns to a request, so a server that compares it against its own host is making a structurally sound check - one that fails only when the check is fed attacker-chosen input. The concrete failure is reflection: a permissive CORS policy, an open redirect, or a proxy that lets a request override the header lets the hostile page cause the browser to present the victim's origin, and the server's allow-list then passes a request that is in fact cross-origin. A hunter confirms this by replaying the state change with a forged Origin equal to the target and observing acceptance, then repeating with an unrelated origin and observing the rejection - the pair is the artifact, because a single accepted request does not distinguish a real defence from a bypassable one. Note also that Origin is absent on some legitimate same-origin deliveries, so a server that fails open when the header is missing reintroduces the same hole.

*Disproof:* The claim is false when the server rejects the request whenever Origin is absent or differs from its own host, when the header cannot be reflected or overridden by any reachable path, or when an independent anti-CSRF token is still required. It is likewise false if the forged-Origin request is refused with 403, and false when the endpoint's effect is not attacker-meaningful or is undone before an attacker could use it.

**The credential half of a CSRF proof is the Set-Cookie header on the login response: when the session cookie carries no SameSite attribute, or SameSite=None, the browser attaches it to the attacker's cross-origin POST automatically, so the forged request arrives pre-authenticated without the attacker ever holding the cookie value.**

This is the piece that makes forgery possible at all, and it is checkable in a single response header before any exploit is attempted. Read the Set-Cookie that establishes the session and ask whether SameSite is absent or None; in that state a hostile page can cause a cross-domain POST to that site and the browser adds the cookie by itself, with no read access to the value from the attacker's context. The counter-case is equally legible: SameSite=Strict confines the cookie to same-origin requests, while Lax still permits top-level navigations using GET, HEAD, OPTIONS and TRACE, which is why a GET-mutating or method-override endpoint stays exposed even under a Lax policy. Report the header as the artifact and let the endpoint replay be the confirmation, so a reviewer can re-check the finding from a login response alone.

*Disproof:* The claim is false when the session cookie is issued SameSite=Strict, or SameSite=Lax on an endpoint that refuses GET and honours no method-override parameter, because the cookie then does not ride along on a cross-origin POST. It is also false where authentication does not ride on an ambient cookie at all - a bearer token the attacker's page cannot read, a per-request signature bound to the body, or a custom header that forces a preflight the server refuses - since no credential is silently attached and there is nothing to forge. A Set-Cookie that is absent entirely, or a cookie the server never checks, does not satisfy the claim either.

**CSRF is proven when one cross-origin POST to a state-changing endpoint, carrying only the victim's ambient session cookie and no anti-CSRF token, returns the same success status and the same durable side effect as the authenticated same-origin baseline request.**

The artifact a reviewer re-runs is a two-request pair, not a status code: first the legitimate authenticated call establishes the baseline, then the identical body is replayed from a page on a foreign origin carrying the same session cookie. The proving observation is convergence - the forged request is not merely accepted, it produces byte-identical server state, so the reviewer can re-read the affected object over the victim's own authenticated session and see the attacker's value there. The absence of a token is a precondition rather than the finding: CWE-1275 makes explicit that a CSRF attack requires several conditions together, including the lack of CSRF tokens and a 'simple' Content-Type header, so a request that is refused on any one of them is not a finding. Keep the two requests identical in method, body and headers apart from Origin, because a divergence means some other control fired and the endpoint is not demonstrably exposed.

*Disproof:* The claim is false if the replayed cross-origin request is refused with 401, 403 or 405, if it is answered with a challenge, a one-time code or any interactive confirmation, if the response body differs from the same-origin baseline, or if re-reading the affected object shows no attacker-supplied value persisted. It is also false where no cross-origin delivery is achievable at all - an endpoint that requires a preflighted custom header or a non-simple Content-Type never leaves the attacker page - and false where the state change is not attacker-meaningful, such as a counter nobody can read.

## Exploitation

**A GraphQL endpoint that enforces CSRF only on POST is open to state-changing mutations triggered by a self-submitted form with method=GET in a logged-in victim's browser.**

GitLab required an X-CSRF-Token header for POST requests to /api/graphql but not for GET, so the backend never expected the token on GET. The researcher built a self-submitting form whose query variable was a createSnippet mutation; visiting the page in a logged-in browser executed the mutation, creating a public snippet on the victim's account. The report was rewarded $2,870 and patched in GitLab 14.0.2.

*Disproof:* Enforce a CSRF token for every HTTP method including GET, or reject GET requests to the GraphQL endpoint entirely.

**Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because most CSRF defenses can be bypassed using attacker-controlled script.**

ks 
 
 
 
 Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid [ REF-1482 ]. 
 For example, use anti-CSRF packages such as the OWASP CSRFGuard. [ REF-330 ] 
 Another example is the ESAPI Session Management control, which includes a component for CSRF. [ REF-45 ] 
 
 
 
 
 
 
 
 
 
 
 Implementation 
 
 
 
 
 
 Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because most CSRF defenses can be bypassed using attacker-controlled script. 
 
 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable ( CWE-330 ). [ REF-332 ] 
 
 
 Note: 
 Note that this can be bypassed using XSS ( CWE-79 ). 
 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 Identify especially dangerous operatio

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ensure that the application is free of cross-site scripting issues ( CWE-79 ), b”) does not occur under a test that isolates that control.

**CMS allows modification of configuration via CSRF attack against the administrator.**

CVE-2005-1947 
 
 
 
 
 Delete a victim's information via a URL or an img tag 
 
 
 
 
 
 
 
 CVE-2005-2059 
 
 
 
 
 Change another user's settings via a URL or an img tag 
 
 
 
 
 
 
 
 CVE-2005-1674 
 
 
 
 
 Perform actions as administrator via a URL or an img tag 
 
 
 
 
 
 
 
 CVE-2009-3520 
 
 
 
 
 modify password for the administrator 
 
 
 
 
 
 
 
 CVE-2009-3022 
 
 
 
 
 CMS allows modification of configuration via CSRF attack against the administrator 
 
 
 
 
 
 
 
 CVE-2009-3759 
 
 
 
 
 web interface allows password changes or stopping a virtual machine via CSRF 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 Resultant 
 
 
 
 (where the weakness is typically related to the presence of so

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CMS allows modification of configuration via CSRF attack against the administrat”) does not occur under a test that isolates that control.

**web interface allows password changes or stopping a virtual machine via CSRF.**

Change another user's settings via a URL or an img tag 
 
 
 
 
 
 
 
 CVE-2005-1674 
 
 
 
 
 Perform actions as administrator via a URL or an img tag 
 
 
 
 
 
 
 
 CVE-2009-3520 
 
 
 
 
 modify password for the administrator 
 
 
 
 
 
 
 
 CVE-2009-3022 
 
 
 
 
 CMS allows modification of configuration via CSRF attack against the administrator 
 
 
 
 
 
 
 
 CVE-2009-3759 
 
 
 
 
 web interface allows password changes or stopping a virtual machine via CSRF 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 Resultant 
 
 
 
 (where the weakness is typically related to the presence of some other weaknesses)
 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Detection
 Methods 
 
 
 
 
 
 Method 
 Details 
 
 
 
 
 
 M

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“web interface allows password changes or stopping a virtual machine via CSRF”) does not occur under a test that isolates that control.

**A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.**

PortSwigger extends the class explicitly: if the target website supports WebSockets, this functionality might be vulnerable to cross-site WebSocket hijacking (CSWSH), which is essentially just a CSRF attack targeting a WebSocket handshake. The mechanism is the same three-part one: an action worth forging (the application treats any message on the socket as an authenticated instruction), automatic ambient credentials (the handshake carries the session cookie, which the browser attaches to the cross-site upgrade), and no unpredictable parameter (the Origin header on the upgrade is often not checked server-side at all). Hunt it where a browser-facing socket exists without an Origin allowlist: subscribe and observe the handshake, then attempt the upgrade from a foreign origin and check whether the server completes it and whether the socket is accepted as the logged-in user.

*Disproof:* The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.

**Rejecting unsafe methods when Sec-Fetch-Site is cross-site, with a mandatory fallback to Origin verification on browsers that omit the headers, blocks CSRF without any token and no client change.**

The Fetch Metadata specification defines Sec-Fetch-Site as the header exposing the relationship between a request initiator's origin and its target's origin, whose valid values are cross-site, same-origin, same-site and none, and it exists precisely for this class of decision. OWASP's server-side policy is concrete: treat cross-site as untrusted for state-changing actions, rejecting POST, PUT, PATCH and DELETE when Sec-Fetch-Site is cross-site; allow same-origin; allow none for user-driven top-level navigations such as bookmarks, typed URLs and explicit form submits; and treat same-site as allowed only if the threat model trusts sibling subdomains. Two requirements are load-bearing when reporting this as a defence. Fetch metadata headers are only sent to potentially trustworthy URLs, so HTTPS must be enforced across the whole application, and because some legacy browsers do not send the Sec-Fetch-* headers, a fallback to standard origin verification headers is a mandatory requirement. Report a SameSite-only or Sec-Fetch-Site-only deployment as incomplete when that fallback is absent.

*Disproof:* The server accepts unsafe methods with Sec-Fetch-Site: cross-site, or the check is present but there is no Origin/Referer fallback so any client omitting the headers is admitted by default.

**A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.**

A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.

HackTricks reference: cross site request forgery bypass (https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md)

*Disproof:* If the endpoint rejects every one of those mutations (method switch, removed/blanked/altered token, replayed or attacker-supplied token, Content-Type change, stripped referer) with the same consistent rejection, the anti-forgery control is holding.

**A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.**

A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.

HackTricks reference: csrf (https://kathan19.gitbook.io/howtohunt/csrf/csrf.md)

*Disproof:* Opening the generated auto-submit page from an origin the target does not trust produces no state change in the victim account, so the page proves nothing.

**A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.**

A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.

HackTricks reference: cross site request forgery bypass (https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md)

*Disproof:* If the endpoint rejects every one of those mutations (method switch, removed/blanked/altered token, replayed or attacker-supplied token, Content-Type change, stripped referer) with the same consistent rejection, the anti-forgery control is holding.

**A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.**

A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.

HackTricks reference: csrf (https://kathan19.gitbook.io/howtohunt/csrf/csrf.md)

*Disproof:* Opening the generated auto-submit page from an origin the target does not trust produces no state change in the victim account, so the page proves nothing.

**A state-changing request replayed from an attacker origin without an anti-CSRF token succeeds when the session cookie carries no effective SameSite restriction.**

Authenticate with a test account, capture a state-changing POST with its cookies, then replay it from a page on a controlled origin with the session cookie attached and no CSRF token. The SameSite strategy works by restricting session cookies to requests originating from the same domain, so if the cookie still rides along the request is accepted without user intent. Confirm server-side state actually changed, not just that a 2xx was returned.

*Disproof:* If the browser withholds the session cookie cross-site, or the server rejects the tokenless replay with 4xx and no state change, the CSRF replay does not reproduce.

## Variations

**SameSite=Lax does not fully mitigate CSRF: browsers treat sibling subdomains as same-site, and Chrome applies Lax by default when no SameSite attribute is set and does not enforce it for top-level POSTs for roughly two minutes, so an attacker-controlled subdomain can drive a cross-site POST that carries the same-parent session cookie.**

PortSwigger explains that a cross-origin request can still be same-site and that Chrome applies Lax by default when no attribute is set, without enforcing the restriction for the first 120 seconds on top-level POST requests. An attacker who controls a sibling subdomain can host a form that POSTs to the target; the browser treats the sibling as same-site and attaches the session cookie, bypassing the Lax protections. PortSwigger advises auditing sibling domains and WebSockets (CSWSH) as part of the same defenses. GitHub's advisory GHSA-92mw-q256-5vwg documents a real-world sibling-subdomain SameSite/Lax misconfiguration combined with missing Content-Type enforcement in Argo CD.

*Disproof:* Set SameSite=Strict on the session cookie, isolate the API on a domain with no sibling subdomains sharing the parent, or otherwise defeat the Lax-by-default window.

**A JSON API that only enforces Content-Type: application/json can be bypassed by posting a text/plain body whose input names are JSON fragments; the browser sends it cross-origin without a CORS preflight, so SameSite session cookies attach and the server parses the form body as valid JSON.**

PortSwigger notes that a JSON endpoint is CSRF-resistant only if it rejects simple request types; if it also accepts a text/plain body (common), a text/plain payload that parses as valid JSON slips through. Because text/plain is a simple request, no CORS preflight is issued and the cross-site POST carries the SameSite session cookie. A server that checks only the Content-Type header, rather than validating JSON through the preflighted application/json path, is exposed.

*Disproof:* Reject application/x-www-form-urlencoded and text/plain for JSON APIs, require a custom header that forces a CORS preflight, or only read JSON through the application/json route.

**A path-traversal routing quirk in the GitHub Enterprise Server management console lets a PUT reach the protected admin endpoint without a valid CSRF token: the router matches the post-traversal path for execution but the pre-traversal path for the CSRF-protection scope.**

CVE-2022-23732: an attacker could submit a crafted form whose action contained post-traversal sequences such as /setup/api/start/..%2f..%2fadmin%2fusers, bypassing the token check that applied to the pre-traversal path and reaching the protected administration endpoint. The flaw affected all versions prior to 3.5 and was fixed in 3.1.19, 3.2.11, 3.3.6, and 3.4.1. GitHub rewarded $10,000.

*Disproof:* The router normalizes the path identically for protection scoping and execution, or the target endpoint refuses traversal sequences.

**Frameworks that enforce CSRF by default do so through a global middleware plus explicit per-view exemptions, so the bypass is not breaking the token scheme - it is finding a view the middleware was told to skip.**

Modern frameworks have made the global-token-missing case rare and pushed the vulnerability into the exemption mechanism. Django's default CsrfViewMiddleware refuses unsafe methods without a token, and csrf_exempt marks a single view as being exempt from the protection the middleware ensures; Django also offers csrf_protect to opt a view back in. Rails does the same by default with default_protect_from_forgery, with protect_from_forgery with: :exception as the manual equivalent. So the productive hunting move is to enumerate the exempt surface rather than to look for absent tokens: legacy AJAX endpoints, webhook receivers, endpoints that were exempted to make a failing integration test pass, and views exempted on the assumption that they are safe because they 'only return data'. The tell in the code and the response is a state-changing view that accepts a cross-site POST and returns success while every neighbouring view returns 403.

*Disproof:* The claim fails when the exemption is not reachable as a state change - a GET-only view, a view bound to a machine-to-machine credential, or an endpoint whose response body is inert data. It also fails if the middleware is not actually installed on that URL prefix, since many frameworks scope middleware by path, so a view can be unprotected simply because it sits outside the middleware's route list rather than because it carries an exemption marker. And if the exempt endpoint independently requires a header, a content type, or a token of another kind, the exemption does not translate into a CSRF finding. Conversely, an exemption that is applied broadly to a whole controller rather than one action is a real finding, not an artefact.

**The naive double-submit cookie pattern is bypassable by any actor able to write a cookie on the target domain, which a vulnerable sibling subdomain, a DNS takeover, or plaintext-HTTP injection onto a non-__Host- cookie all provide.**

OWASP now marks the pattern with an explicit warning: the Naive Double-Submit Cookie pattern is bypassable by an attacker who can write cookies on the target domain, e.g. via a vulnerable sibling subdomain, DNS takeover, or plaintext-HTTP cookie injection on a non-__Host- cookie, and for new code the Signed Double-Submit pattern should be used instead. PortSwigger gives the mechanism from the attacker's side: the cookie-setting behaviour does not even need to exist within the same web application as the CSRF vulnerability, since any other application within the same DNS domain can potentially be leveraged to set cookies in the targeted application if the controlled cookie has suitable scope, with the example of a cookie-setting function on staging.demo.normal-website.com placing a cookie submitted to secure.normal-website.com. The naive pattern also validates the cookie value rather than an explicit client submission, which is exactly the property an attacker with cookie-write access can satisfy.

*Disproof:* The double-submit cookie is signed with a server secret and bound to the session id, is prefixed __Host- so it cannot be overwritten from a sibling or over plaintext HTTP, and the server additionally requires the value in a custom header or form parameter rather than trusting the cookie.

**SameSite=Lax still attaches the session cookie to a top-level GET navigation, so a server that accepts a form submission over GET, or honours a framework method-override parameter, reopens CSRF despite SameSite being set.**

SameSite=Lax permits the cookie on cross-site top-level navigations, which is enough when the endpoint does not enforce a method. PortSwigger: in practice servers aren't always fussy about whether they receive a GET or a POST request to a given endpoint, even those expecting a form submission, so with Lax session cookies, either explicit or from the browser default, an attacker may still perform a CSRF attack by eliciting a GET from the victim's browser, and as long as the request involves a top-level navigation the browser will still include the victim's session cookie. The worked example is a one-line document.location assignment to /account/transfer-payment?recipient=hacker&amount=1000000. The same page adds the escalation: even if an ordinary GET is not allowed, some frameworks let the method in the request line be overridden, and Symfony's _method form parameter takes precedence over the normal method for routing purposes. So the test is the pair, not the cookie attribute: identify method-override support, then drive the POST endpoint through it over GET.

*Disproof:* The endpoint refuses GET with 405 regardless of any override parameter, honours no framework method override, or the session cookie is SameSite=Strict so a top-level cross-site navigation does not carry it.

**SameSite cookie protection is a site-scoped, not origin-scoped, control, so JavaScript execution on any sibling domain of the same site defeats it completely.**

PortSwigger draws the distinction the defence depends on: the difference between a site and an origin is their scope, a site encompasses multiple domain names whereas an origin only includes one, and crucially a cross-origin request can still be same-site, but not the other way around. The consequence for CSRF is stated directly: any vulnerability enabling arbitrary JavaScript execution can be abused to bypass site-based defenses on other domains belonging to the same site. A second route in the same family is a client-side redirect gadget on the target site that constructs its destination from attacker-controllable input, because the resulting request is treated as an ordinary standalone request, is same-site, and therefore includes all cookies for the site regardless of any restrictions in place. Note the equivalent attack is not possible with server-side redirects, which browsers treat as still cross-site. Hunt this as a same-site precondition, not as a SameSite misconfiguration.

*Disproof:* The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.

**A CSRF token accepted from a global pool of issued tokens, rather than bound to the requesting session, is defeated by the attacker logging in with their own account and feeding the victim a token the attacker legitimately holds.**

PortSwigger: some applications do not validate that the token belongs to the same session as the user making the request, instead maintaining a global pool of tokens it has issued and accepting any token in that pool, so the attacker logs in with their own account, obtains a valid token, and feeds it to the victim. The same page documents the near-miss variant where the token is tied to a cookie but not to the cookie that tracks the session, which easily occurs when an application employs two different frameworks, one for session handling and one for CSRF protection, that are not integrated together. OWASP's current position is stronger still: the most secure implementation of the Double Submit Cookie pattern is the signed variant that explicitly ties tokens to the user's authenticated session, and simply signing tokens without session binding provides minimal protection and remains vulnerable to cookie injection attacks. Test: capture a token as user A, submit it as user B in the same session, then submit A's token against B's cookie.

*Disproof:* A token issued to one session is rejected when presented by a different session, whether compared against a server-side per-session value, an HMAC bound to the session id, or a signed double-submit cookie carrying the same session id.

**A CSRF check written as validate-if-present is bypassed by deleting the whole token parameter, because an absent parameter is never compared against the expected value.**

PortSwigger's second common flaw: some applications correctly validate the token when it is present but skip the validation if the token is omitted, so the attacker removes the entire parameter containing the token, not just its value. OWASP's synchronizer-token requirement is the corresponding positive control: the server-side component must verify the existence and validity of the token in that request and compare it to the token found in the user session, and the request should be rejected if that token was not found within the request or the value provided does not match. The distinction to test for is a missing parameter versus a wrong parameter, so submit the endpoint four ways: correct token, wrong token, token present but empty, and token parameter deleted entirely. A 403 only for the wrong-token case with a 200 for the deleted case is a confirmed bypass.

*Disproof:* Deleting the token parameter produces the same rejection status and body as submitting a wrong token, and no state change is committed in either case.

**A CSRF defence that validates the anti-CSRF token only on POST is bypassed by reissuing the identical state change as a GET, because many endpoints accept either method.**

PortSwigger names validation that depends on the request method as one of the common flaws: some applications correctly validate the token when the request uses the POST method but skip the validation when the GET method is used, so the attacker switches to GET to bypass validation entirely, e.g. GET /email/change?email=pwned@evil-user.net carrying the victim's session cookie. CWE-352 states the same rule from the mitigation side: do not use the GET method for any request that triggers a state change. Test procedure: take a POST endpoint that demonstrably enforces a token, then replay the identical parameter set as GET, PUT and HEAD and compare responses. A GET variant that returns 200 and performs the action is a confirmed bypass, and the finding is usually higher severity than the original because the exploit is a single URL that needs no attacker-hosted form.

*Disproof:* The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.

**Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken.**

Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken.

HackTricks reference: cross site request forgery bypass (https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md)

*Disproof:* A framed load of the endpoint that cannot induce the victim to perform the action shows the framing path does not deliver the cross-site request forgery.

**Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken.**

Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken.

HackTricks reference: cross site request forgery bypass (https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md)

*Disproof:* A framed load of the endpoint that cannot induce the victim to perform the action shows the framing path does not deliver the cross-site request forgery.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `csrf-same-site-xss-to-state-change` — Same-site sibling script execution to forged state change on the real origin (goal: `Use script execution on a sibling domain of the target site to defeat SameSite and the CSRF token, then commit a state-changing action on the real origin that the server treats as legitimate.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A CSRF validation failure that occurs only after a fresh login is token rotation working as designed, not a control failure - the pre-login form legitimately holds a stale token.**

A frustrating class of CSRF report looks like this: the endpoint rejects your request, so the tester concludes either that the token is validated in a broken way or, worse, that the endpoint is 'not properly protected'. The actual mechanism is mundane and is documented by Django: for security reasons the token secret is changed each time a user logs in, so a page rendered before the login carries a secret that is no longer current and any form generated from it fails validation until the page is reloaded. The field lesson is to timestamp your observation: if the 403 appears only on a token minted before the login, the defence is holding. The corollary for real hunting is the inverse - because the secret rotates at login, a token captured before the victim's session changes is dead, so CSRF payloads must be built against a token fetched after authentication, and an attacker-hosted page never has one.

*Disproof:* The rule is wrong if the failure persists after the page is reloaded post-login, which means the mismatch is structural rather than temporal - a session-rotation bug, a token stored in the session while the form reads a cookie, a per-request mask the server never unmasks, or a multi-tab token cache serving a value from a different session. It is also wrong if the secret does not actually rotate but the failure still correlates with login, which points at a login handler that rewrites the cookie without updating the stored secret. And rotation at login is a genuine weakness in one specific case: an endpoint that accepts the previous secret as well as the current one, so a token captured before the victim's login still validates afterwards.

**An endpoint that answers only safe methods (GET/HEAD) and only reads state is not a CSRF finding for having no anti-CSRF token: the CSRF precondition is that the victim sends a request that triggers a state change, and a GET that changes nothing cannot be ridden.**

The passive scanners that report this alert look at HTML forms for a token, not at whether the form changes anything, so every search box, filter, pagination control, autocomplete and catalogue sorter becomes a hit. Reject on the method and the effect, not on the absence of a hidden field: replay the request cross-site with the victim's cookie and observe whether any server-side state moved. If the response is the same read-only result set, the token protects nothing. ZAP's own remediation language states the boundary - do not use the GET method for any request that triggers a state change - which makes the state change, not the token, the thing being protected. CAPEC-62 names the mechanism CSRF actually rides: the persistent, implicit trust applications place in user session cookies, so every subsequent transaction in that session is authenticated by the cookie alone, which is only dangerous when there is a transaction worth forging.

*Disproof:* It IS CSRF if the same GET (a) mutates state - deletes, archives, toggles, subscribes, confirms, transfers - (b) triggers a state change through a redirect or JS handler the GET returns, or (c) the endpoint accepts POST as an alias for the same action. Prove it by replaying the cross-site GET with a victim cookie and observing a server-side state delta, not by reading the HTML form for a token.

**A CSRF finding against a low-privilege victim is still a real finding; the privileged-role case raises impact but must not be reported as a distinct or additional vulnerability.**

PortSwigger's impact statement makes the privileged case a severity multiplier, not a separate weakness: in a successful CSRF attack the attacker causes the victim to carry out an action unintentionally, which might be to change the email address on their account, change their password, or make a funds transfer, and depending on the nature of the action the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality. Two consequences for reporting. First, do not discard a same-origin state change just because the account you tested with is unprivileged, since the same endpoint reached with an administrator's cookie is a different impact, not a different bug. Second, do not file one finding per victim role, which double-counts a single missing validation. The disproof that would clear the item is a server-side check that ties the request to intentional user action regardless of the account's role, such as a re-authentication step or a synchronizer token validated on every unsafe method.

*Disproof:* The endpoint enforces a server-side proof of intentional user action, such as a synchronizer token validated on every unsafe method, a re-authentication challenge, or a same-origin header check with fallback, in which case the role of the victim changes the impact of a compromise but cannot create the forgery.

**An attacker who supplies both halves of a synchroniser-token pair - a CSRF cookie they choose plus a POST field containing the same value - has not demonstrated CSRF, because a cross-origin attacker has no channel to write the victim's cookie.**

This is the single most common false positive in CSRF testing and it looks exactly like a working exploit if you only look at the request. A hunter curls the endpoint with Cookie: csrf=abc and a matching csrf field abc, sees the state change succeed, and reports it. But the synchroniser-token pattern is explicitly designed so that the two halves live in different places: the cookie is set by the target origin and the hidden field is read from that origin's own page. A cross-site attacker cannot set a cookie for the target domain and cannot read the token out of a page they do not control, so they cannot produce a matched pair. Django states this as a design property rather than a vulnerability. The correct test is whether an attacker on a different origin can cause the browser to send a matched pair without any attacker-chosen cookie value - and the way to demonstrate that is a real cross-origin page with the victim's session, not a hand-crafted request.

*Disproof:* The rule breaks down in two real situations. First, subdomain or sibling-origin cookie injection: if any attacker-reachable host can set a cookie on the parent domain - via a cookie-tossing endpoint, an open redirect onto the parent, a permissive Domain attribute, or XSS on a subdomain - then the attacker does have a channel to plant the cookie half of the pair and the synchroniser token collapses. Second, if the application accepts the token from a header or query parameter that a simple cross-origin request can set, or compares only a substring or a truncated value, the pair is forgeable without cookie write at all. A finding backed by either of those is genuine CSRF despite the pairing.

**An API endpoint authenticated only by an Authorization header and no ambient cookie is not CSRF-exploitable, because no cross-origin page can make the browser attach the credential.**

Discard the report when the endpoint authenticates from the Authorization header, a bearer token in a JSON body, or a client cert, and your forged cross-origin form or fetch could not set that header without a CORS preflight the target refused. The finding survives when the endpoint also accepts a cookie or other browser-attached credential, when the replay succeeded with a header your page set from a permissive CORS origin, or when the vulnerable action is a GET that needs no preflight.

*Disproof:* A permissive Access-Control-Allow-Origin with Allow-Credentials makes the credential attachable cross-origin, and an API that mirrors the Authorization value into a cookie, or accepts a token in a query string that a cross-site img or form can carry, restores the vector with no cookie present at all.

**A state-changing POST that succeeds from an attacker page is not CSRF when the session cookie is SameSite=Strict or SameSite=Lax, because the browser withholds it on cross-site subresource requests.**

Discard the finding when the auth cookie you captured in the replay carries SameSite=Strict or SameSite=Lax, or the Set-Cookie on login sets it without a SameSite=None; Secure pair, because the browser then has no credential to attach to the forged request and the forged request is anonymous. The finding survives only when the session cookie is SameSite=None, or when the forged request succeeded with a credential the browser attached automatically rather than one your page injected.

*Disproof:* A SameSite=Lax cookie is still sent on a cross-site top-level GET navigation, so any state change reachable by GET, or any endpoint that also honours a cookie-less cross-site POST because the session is re-established from another channel, is genuinely exploitable despite the attribute.

## Validation

**CSRF is only reportable on an endpoint whose effect survives being reached without the victim's intent, so the decisive evidence is a state change caused by a cross-site request, not a 200 on a hand-rolled POST.**

RFC 9110's definition of a safe method is the hinge: a method is safe when the client does not request and does not expect any state change on the origin server. That is why almost every CSRF defence exempts GET - and it is also why a GET that does mutate state is the highest-value CSRF target in an application, because the exemption is applied on the method name, not on the behaviour. Django puts the same ordering first in its own guidance: ensure GET and other safe methods are side effect free, then protect the unsafe ones. So the validation sequence is: find a request whose verb is nominally safe but whose effect is not, or an unsafe verb with no token check; then prove the effect with a cross-origin delivery carrying the victim's session; then read the victim's state afterwards and show it changed. A replayed POST in your own client proves nothing about cross-site reachability, and a GET endpoint with no token is only a finding if you can show it mutates.

*Disproof:* The rule is void when the effect is not observable and not attacker-meaningful - a GET that only increments a counter nobody can read, writes a cache entry, or logs a hit is not a reportable CSRF even though it technically mutates. It also fails if the endpoint's state change requires an anti-CSRF artefact the attacker cannot obtain even cross-site, such as a one-time code delivered out of band. And a cross-origin delivery is not achievable for every endpoint class: a request that requires a preflighted custom header, a non-simple Content-Type, or a fetch with credentials omitted never leaves the attacker page, so 'no cross-origin vector' is a real and reportable negative, not an excuse.

**A cross-site POST that changes server state while carrying the victim's ambient cookie and no anti-CSRF token proves CSRF rather than a same-origin caller.**

Step: replay the victim's state-changing request as a bare form POST from an attacker origin, with no custom request header and no token parameter, and record the response status against a baseline captured with the same cookie sent as a same-origin client request. The claim is proven by the differential, not by the 200: the cross-site request produces the same state change and the same response as the same-origin one, and a second read of the affected resource shows the change persisted. The absence of the token from the replayed request is the observation that separates this from an authorization failure, because a request that is rejected unauthenticated never reaches the state-changing code. Note that ambient credentials alone make this reachable, so the precondition is a cookie the browser attaches automatically.

*Disproof:* If the replayed cross-site request is rejected with 401 or 403, or if the state change is absent when compared against the same-origin baseline, then no CSRF exists and the observation is a same-origin authorization control doing its job.

**To decide this case, observe: Discard the finding when the auth cookie you captured in the replay carries SameSite=Strict or SameSite=Lax, or the Set-Cookie on login sets it without a SameSite=None; Secure pair, because the browser then has no credential to attach to the forged request and the forged request is anonymous.**

Derived from csrf.fprule.samesite_cookie_blocks_cross_site_credential, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (csrf.fprule.samesite_cookie_blocks_cross_site_credential) states the full boundary.

## Impact

**An OAuth and integrations linking flow with improper CSRF token validation lets an attacker associate the attacker's third-party account with the victim's account with one click, then issue unauthorized calls through the linked integration, achieving account takeover of the linked integration.**

The frontend built an authorization link to an OAuth2 endpoint from a session token and a CSRF token whose validation was improper, putting all customers at risk. One click from the victim linked the victim's GitHub account to the attacker's account, and the attacker used the victim's authorized account to make arbitrary calls through the Tray.io GraphQL. Impact: account takeover of the linked integration.

*Disproof:* Bind the CSRF token to the user and to the specific OAuth callback state, require user interaction to complete consent, and validate the OAuth state parameter.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/the-growing-concern-of-api-security>
- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/product-tech/2017/01/26/cross-site-request-forgery-what-happened-to-the-sleeping-giant>
- **capec.mitre.org** (standard)
  - <https://capec.mitre.org/data/definitions/62.html>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- **cwe.mitre.org** (research)
  - <https://cwe.mitre.org/data/definitions/1275.html>
  - <https://cwe.mitre.org/data/definitions/352.html>
- **developer.mozilla.org** (writeup)
  - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS>
  - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
- **docs.djangoproject.com** (writeup)
  - <https://docs.djangoproject.com/en/5.0/ref/csrf/>
- **github.com** (primary)
  - <https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg>
- **guides.rubyonrails.org** (writeup)
  - <https://guides.rubyonrails.org/security.html>
- **hackerone.com** (hackerone)
  - <https://hackerone.com/reports/1122408>
  - <https://hackerone.com/reports/1483327>
  - <https://hackerone.com/reports/1497169>
  - <https://hackerone.com/reports/1727221>
- **httpwg.org** (docs)
  - <https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html>
  - <https://httpwg.org/specs/rfc9110.html>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>
  - <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>
- **nvd.nist.gov** (primary)
  - <https://nvd.nist.gov/vuln/detail/CVE-2022-23732>
- **owasp.org** (cheatsheet)
  - <https://owasp.org/www-community/attacks/csrf>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/csrf>
  - <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
  - <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **projectdiscovery.io** (research)
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc6265.html>
  - <https://www.rfc-editor.org/rfc/rfc6265.txt>
  - <https://www.rfc-editor.org/rfc/rfc6454.html>
  - <https://www.rfc-editor.org/rfc/rfc9110.txt>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/how-to-protect-node-js-apps-from-csrf-attacks/>
- **w3.org** (standard)
  - <https://www.w3.org/TR/fetch-metadata/>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/10202/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
