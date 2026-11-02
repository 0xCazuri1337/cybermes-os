# Methodology — Cross-Site Request Forgery

> Derived from 26 verified items. Regenerate with `python -m wks.methodgen --class csrf --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.

**References.** CWE-352 · A01:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.**

PortSwigger states three conditions must be in place for a CSRF attack to be possible: a relevant action (privileged, such as modifying permissions for other users, or any action on user-specific data such as changing the user's own password); cookie-based session handling, where the application relies solely on session cookies to identify the user and there is no other mechanism for tracking sessions or validating requests; and no unpredictable request parameters, meaning the requests that perform the action contain no parameters whose values the attacker cannot determine or guess. The password-change example makes the third condition concrete: the function is not vulnerable if the attacker needs to know the value of the existing password. Triage use: a state-changing POST protected by a re-typed password fails condition three and is not a CSRF finding, no matter what the cookies do. Testing a CSRF candidate means establishing all three, not one.

- *Disproof:* Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [portswigger.net](https://portswigger.net/web-security/csrf)

**A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.**

A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.

HackTricks reference: csrf (https://kathan19.gitbook.io/howtohunt/csrf/csrf.md)

- *Disproof:* If every request reachable at the endpoint is read-only and produces no state change for the victim, the cross-site request forgery claim is refuted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1275.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/csrf/csrf.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.txt)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.**

A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.

HackTricks reference: cross site request forgery bypass (https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md)

- *Disproof:* If the endpoint rejects every one of those mutations (method switch, removed/blanked/altered token, replayed or attacker-supplied token, Content-Type change, stripped referer) with the same consistent rejection, the anti-forgery control is holding.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1275.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.txt)

**A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.**

PortSwigger extends the class explicitly: if the target website supports WebSockets, this functionality might be vulnerable to cross-site WebSocket hijacking (CSWSH), which is essentially just a CSRF attack targeting a WebSocket handshake. The mechanism is the same three-part one: an action worth forging (the application treats any message on the socket as an authenticated instruction), automatic ambient credentials (the handshake carries the session cookie, which the browser attaches to the cross-site upgrade), and no unpredictable parameter (the Origin header on the upgrade is often not checked server-side at all). Hunt it where a browser-facing socket exists without an Origin allowlist: subscribe and observe the handshake, then attempt the upgrade from a foreign origin and check whether the server completes it and whether the socket is accepted as the logged-in user.

- *Disproof:* The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)

**A state-changing request replayed from an attacker origin without an anti-CSRF token succeeds when the session cookie carries no effective SameSite restriction.**

Authenticate with a test account, capture a state-changing POST with its cookies, then replay it from a page on a controlled origin with the session cookie attached and no CSRF token. The SameSite strategy works by restricting session cookies to requests originating from the same domain, so if the cookie still rides along the request is accepted without user intent. Confirm server-side state actually changed, not just that a 2xx was returned.

- *Disproof:* If the browser withholds the session cookie cross-site, or the server rejects the tokenless replay with 4xx and no state change, the CSRF replay does not reproduce.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/the-growing-concern-of-api-security); [snyk.io](https://snyk.io/blog/how-to-protect-node-js-apps-from-csrf-attacks/)

**Rejecting unsafe methods when Sec-Fetch-Site is cross-site, with a mandatory fallback to Origin verification on browsers that omit the headers, blocks CSRF without any token and no client change.**

The Fetch Metadata specification defines Sec-Fetch-Site as the header exposing the relationship between a request initiator's origin and its target's origin, whose valid values are cross-site, same-origin, same-site and none, and it exists precisely for this class of decision. OWASP's server-side policy is concrete: treat cross-site as untrusted for state-changing actions, rejecting POST, PUT, PATCH and DELETE when Sec-Fetch-Site is cross-site; allow same-origin; allow none for user-driven top-level navigations such as bookmarks, typed URLs and explicit form submits; and treat same-site as allowed only if the threat model trusts sibling subdomains. Two requirements are load-bearing when reporting this as a defence. Fetch metadata headers are only sent to potentially trustworthy URLs, so HTTPS must be enforced across the whole application, and because some legacy browsers do not send the Sec-Fetch-* headers, a fallback to standard origin verification headers is a mandatory requirement. Report a SameSite-only or Sec-Fetch-Site-only deployment as incomplete when that fallback is absent.

- *Disproof:* The server accepts unsafe methods with Sec-Fetch-Site: cross-site, or the check is present but there is no Origin/Referer fallback so any client omitting the headers is admitted by default.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [w3.org](https://www.w3.org/TR/fetch-metadata/)

**A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.**

A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.

HackTricks reference: csrf (https://kathan19.gitbook.io/howtohunt/csrf/csrf.md)

- *Disproof:* Opening the generated auto-submit page from an origin the target does not trust produces no state change in the victim account, so the page proves nothing.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1275.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/csrf/csrf.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.txt)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A cross-site POST that changes server state while carrying the victim's ambient cookie and no anti-CSRF token proves CSRF rather than a same-origin caller.**

Step: replay the victim's state-changing request as a bare form POST from an attacker origin, with no custom request header and no token parameter, and record the response status against a baseline captured with the same cookie sent as a same-origin client request. The claim is proven by the differential, not by the 200: the cross-site request produces the same state change and the same response as the same-origin one, and a second read of the affected resource shows the change persisted. The absence of the token from the replayed request is the observation that separates this from an authorization failure, because a request that is rejected unauthenticated never reaches the state-changing code. Note that ambient credentials alone make this reachable, so the precondition is a cookie the browser attaches automatically.

- *Disproof:* If the replayed cross-site request is rejected with 401 or 403, or if the state change is absent when compared against the same-origin baseline, then no CSRF exists and the observation is a same-origin authorization control doing its job.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/product-tech/2017/01/26/cross-site-request-forgery-what-happened-to-the-sleeping-giant); [w3.org](https://www.w3.org/TR/fetch-metadata/)

**CSRF is only reportable on an endpoint whose effect survives being reached without the victim's intent, so the decisive evidence is a state change caused by a cross-site request, not a 200 on a hand-rolled POST.**

RFC 9110's definition of a safe method is the hinge: a method is safe when the client does not request and does not expect any state change on the origin server. That is why almost every CSRF defence exempts GET - and it is also why a GET that does mutate state is the highest-value CSRF target in an application, because the exemption is applied on the method name, not on the behaviour. Django puts the same ordering first in its own guidance: ensure GET and other safe methods are side effect free, then protect the unsafe ones. So the validation sequence is: find a request whose verb is nominally safe but whose effect is not, or an unsafe verb with no token check; then prove the effect with a cross-origin delivery carrying the victim's session; then read the victim's state afterwards and show it changed. A replayed POST in your own client proves nothing about cross-site reachability, and a GET endpoint with no token is only a finding if you can show it mutates.

- *Disproof:* The rule is void when the effect is not observable and not attacker-meaningful - a GET that only increments a counter nobody can read, writes a cache entry, or logs a hit is not a reportable CSRF even though it technically mutates. It also fails if the endpoint's state change requires an anti-CSRF artefact the attacker cannot obtain even cross-site, such as a one-time code delivered out of band. And a cross-origin delivery is not achievable for every endpoint class: a request that requires a preflighted custom header, a non-simple Content-Type, or a fetch with credentials omitted never leaves the attacker page, so 'no cross-origin vector' is a real and reportable negative, not an excuse.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/ref/csrf/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.txt)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An API endpoint authenticated only by an Authorization header and no ambient cookie is not CSRF-exploitable, because no cross-origin page can make the browser attach the credential.**

Discard the report when the endpoint authenticates from the Authorization header, a bearer token in a JSON body, or a client cert, and your forged cross-origin form or fetch could not set that header without a CORS preflight the target refused. The finding survives when the endpoint also accepts a cookie or other browser-attached credential, when the replay succeeded with a header your page set from a permissive CORS origin, or when the vulnerable action is a GET that needs no preflight.

- *Disproof:* A permissive Access-Control-Allow-Origin with Allow-Credentials makes the credential attachable cross-origin, and an API that mirrors the Authorization value into a cookie, or accepts a token in a query string that a cross-site img or form can carry, restores the vector with no cookie present at all.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**An endpoint that answers only safe methods (GET/HEAD) and only reads state is not a CSRF finding for having no anti-CSRF token: the CSRF precondition is that the victim sends a request that triggers a state change, and a GET that changes nothing cannot be ridden.**

The passive scanners that report this alert look at HTML forms for a token, not at whether the form changes anything, so every search box, filter, pagination control, autocomplete and catalogue sorter becomes a hit. Reject on the method and the effect, not on the absence of a hidden field: replay the request cross-site with the victim's cookie and observe whether any server-side state moved. If the response is the same read-only result set, the token protects nothing. ZAP's own remediation language states the boundary - do not use the GET method for any request that triggers a state change - which makes the state change, not the token, the thing being protected. CAPEC-62 names the mechanism CSRF actually rides: the persistent, implicit trust applications place in user session cookies, so every subsequent transaction in that session is authenticated by the cookie alone, which is only dangerous when there is a transaction worth forging.

- *Disproof:* It IS CSRF if the same GET (a) mutates state - deletes, archives, toggles, subscribes, confirms, transfers - (b) triggers a state change through a redirect or JS handler the GET returns, or (c) the endpoint accepts POST as an alias for the same action. Prove it by replaying the cross-site GET with a victim cookie and observing a server-side state delta, not by reading the HTML form for a token.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/62.html); [zaproxy.org](https://www.zaproxy.org/docs/alerts/10202/)

**A state-changing POST that succeeds from an attacker page is not CSRF when the session cookie is SameSite=Strict or SameSite=Lax, because the browser withholds it on cross-site subresource requests.**

Discard the finding when the auth cookie you captured in the replay carries SameSite=Strict or SameSite=Lax, or the Set-Cookie on login sets it without a SameSite=None; Secure pair, because the browser then has no credential to attach to the forged request and the forged request is anonymous. The finding survives only when the session cookie is SameSite=None, or when the forged request succeeded with a credential the browser attached automatically rather than one your page injected.

- *Disproof:* A SameSite=Lax cookie is still sent on a cross-site top-level GET navigation, so any state change reachable by GET, or any endpoint that also honours a cookie-less cross-site POST because the session is re-established from another channel, is genuinely exploitable despite the attribute.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**A CSRF validation failure that occurs only after a fresh login is token rotation working as designed, not a control failure - the pre-login form legitimately holds a stale token.**

A frustrating class of CSRF report looks like this: the endpoint rejects your request, so the tester concludes either that the token is validated in a broken way or, worse, that the endpoint is 'not properly protected'. The actual mechanism is mundane and is documented by Django: for security reasons the token secret is changed each time a user logs in, so a page rendered before the login carries a secret that is no longer current and any form generated from it fails validation until the page is reloaded. The field lesson is to timestamp your observation: if the 403 appears only on a token minted before the login, the defence is holding. The corollary for real hunting is the inverse - because the secret rotates at login, a token captured before the victim's session changes is dead, so CSRF payloads must be built against a token fetched after authentication, and an attacker-hosted page never has one.

- *Disproof:* The rule is wrong if the failure persists after the page is reloaded post-login, which means the mismatch is structural rather than temporal - a session-rotation bug, a token stored in the session while the form reads a cookie, a per-request mask the server never unmasks, or a multi-tab token cache serving a value from a different session. It is also wrong if the secret does not actually rotate but the failure still correlates with login, which points at a login handler that rewrites the cookie without updating the stored secret. And rotation at login is a genuine weakness in one specific case: an endpoint that accepts the previous secret as well as the current one, so a token captured before the victim's login still validates afterwards.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/ref/csrf/); [guides.rubyonrails.org](https://guides.rubyonrails.org/security.html)

**An attacker who supplies both halves of a synchroniser-token pair - a CSRF cookie they choose plus a POST field containing the same value - has not demonstrated CSRF, because a cross-origin attacker has no channel to write the victim's cookie.**

This is the single most common false positive in CSRF testing and it looks exactly like a working exploit if you only look at the request. A hunter curls the endpoint with Cookie: csrf=abc and a matching csrf field abc, sees the state change succeed, and reports it. But the synchroniser-token pattern is explicitly designed so that the two halves live in different places: the cookie is set by the target origin and the hidden field is read from that origin's own page. A cross-site attacker cannot set a cookie for the target domain and cannot read the token out of a page they do not control, so they cannot produce a matched pair. Django states this as a design property rather than a vulnerability. The correct test is whether an attacker on a different origin can cause the browser to send a matched pair without any attacker-chosen cookie value - and the way to demonstrate that is a real cross-origin page with the victim's session, not a hand-crafted request.

- *Disproof:* The rule breaks down in two real situations. First, subdomain or sibling-origin cookie injection: if any attacker-reachable host can set a cookie on the parent domain - via a cookie-tossing endpoint, an open redirect onto the parent, a permissive Domain attribute, or XSS on a subdomain - then the attacker does have a channel to plant the cookie half of the pair and the synchroniser token collapses. Second, if the application accepts the token from a header or query parameter that a simple cross-origin request can set, or compares only a substring or a truncated value, the pair is forgeable without cookie write at all. A finding backed by either of those is genuine CSRF despite the pairing.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/ref/csrf/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6265.txt)

**A CSRF finding against a low-privilege victim is still a real finding; the privileged-role case raises impact but must not be reported as a distinct or additional vulnerability.**

PortSwigger's impact statement makes the privileged case a severity multiplier, not a separate weakness: in a successful CSRF attack the attacker causes the victim to carry out an action unintentionally, which might be to change the email address on their account, change their password, or make a funds transfer, and depending on the nature of the action the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality. Two consequences for reporting. First, do not discard a same-origin state change just because the account you tested with is unprivileged, since the same endpoint reached with an administrator's cookie is a different impact, not a different bug. Second, do not file one finding per victim role, which double-counts a single missing validation. The disproof that would clear the item is a server-side check that ties the request to intentional user action regardless of the account's role, such as a re-authentication step or a synchronizer token validated on every unsafe method.

- *Disproof:* The endpoint enforces a server-side proof of intentional user action, such as a synchronizer token validated on every unsafe method, a re-authentication challenge, or a same-origin header check with fallback, in which case the role of the victim changes the impact of a compromise but cannot create the forgery.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [portswigger.net](https://portswigger.net/web-security/csrf)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A CSRF defence that validates the anti-CSRF token only on POST is bypassed by reissuing the identical state change as a GET, because many endpoints accept either method.**

PortSwigger names validation that depends on the request method as one of the common flaws: some applications correctly validate the token when the request uses the POST method but skip the validation when the GET method is used, so the attacker switches to GET to bypass validation entirely, e.g. GET /email/change?email=pwned@evil-user.net carrying the victim's session cookie. CWE-352 states the same rule from the mitigation side: do not use the GET method for any request that triggers a state change. Test procedure: take a POST endpoint that demonstrably enforces a token, then replay the identical parameter set as GET, PUT and HEAD and compare responses. A GET variant that returns 200 and performs the action is a confirmed bypass, and the finding is usually higher severity than the original because the exploit is a single URL that needs no attacker-hosted form.

- *Disproof:* The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-token-validation)

**SameSite=Lax still attaches the session cookie to a top-level GET navigation, so a server that accepts a form submission over GET, or honours a framework method-override parameter, reopens CSRF despite SameSite being set.**

SameSite=Lax permits the cookie on cross-site top-level navigations, which is enough when the endpoint does not enforce a method. PortSwigger: in practice servers aren't always fussy about whether they receive a GET or a POST request to a given endpoint, even those expecting a form submission, so with Lax session cookies, either explicit or from the browser default, an attacker may still perform a CSRF attack by eliciting a GET from the victim's browser, and as long as the request involves a top-level navigation the browser will still include the victim's session cookie. The worked example is a one-line document.location assignment to /account/transfer-payment?recipient=hacker&amount=1000000. The same page adds the escalation: even if an ordinary GET is not allowed, some frameworks let the method in the request line be overridden, and Symfony's _method form parameter takes precedence over the normal method for routing purposes. So the test is the pair, not the cookie attribute: identify method-override support, then drive the POST endpoint through it over GET.

- *Disproof:* The endpoint refuses GET with 405 regardless of any override parameter, honours no framework method override, or the session cookie is SameSite=Strict so a top-level cross-site navigation does not carry it.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)

**A CSRF check written as validate-if-present is bypassed by deleting the whole token parameter, because an absent parameter is never compared against the expected value.**

PortSwigger's second common flaw: some applications correctly validate the token when it is present but skip the validation if the token is omitted, so the attacker removes the entire parameter containing the token, not just its value. OWASP's synchronizer-token requirement is the corresponding positive control: the server-side component must verify the existence and validity of the token in that request and compare it to the token found in the user session, and the request should be rejected if that token was not found within the request or the value provided does not match. The distinction to test for is a missing parameter versus a wrong parameter, so submit the endpoint four ways: correct token, wrong token, token present but empty, and token parameter deleted entirely. A 403 only for the wrong-token case with a 200 for the deleted case is a confirmed bypass.

- *Disproof:* Deleting the token parameter produces the same rejection status and body as submitting a wrong token, and no state change is committed in either case.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-token-validation)

**SameSite cookie protection is a site-scoped, not origin-scoped, control, so JavaScript execution on any sibling domain of the same site defeats it completely.**

PortSwigger draws the distinction the defence depends on: the difference between a site and an origin is their scope, a site encompasses multiple domain names whereas an origin only includes one, and crucially a cross-origin request can still be same-site, but not the other way around. The consequence for CSRF is stated directly: any vulnerability enabling arbitrary JavaScript execution can be abused to bypass site-based defenses on other domains belonging to the same site. A second route in the same family is a client-side redirect gadget on the target site that constructs its destination from attacker-controllable input, because the resulting request is treated as an ordinary standalone request, is same-site, and therefore includes all cookies for the site regardless of any restrictions in place. Note the equivalent attack is not possible with server-side redirects, which browsers treat as still cross-site. Hunt this as a same-site precondition, not as a SameSite misconfiguration.

- *Disproof:* The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)

**A CSRF token accepted from a global pool of issued tokens, rather than bound to the requesting session, is defeated by the attacker logging in with their own account and feeding the victim a token the attacker legitimately holds.**

PortSwigger: some applications do not validate that the token belongs to the same session as the user making the request, instead maintaining a global pool of tokens it has issued and accepting any token in that pool, so the attacker logs in with their own account, obtains a valid token, and feeds it to the victim. The same page documents the near-miss variant where the token is tied to a cookie but not to the cookie that tracks the session, which easily occurs when an application employs two different frameworks, one for session handling and one for CSRF protection, that are not integrated together. OWASP's current position is stronger still: the most secure implementation of the Double Submit Cookie pattern is the signed variant that explicitly ties tokens to the user's authenticated session, and simply signing tokens without session binding provides minimal protection and remains vulnerable to cookie injection attacks. Test: capture a token as user A, submit it as user B in the same session, then submit A's token against B's cookie.

- *Disproof:* A token issued to one session is rejected when presented by a different session, whether compared against a server-side per-session value, an HMAC bound to the session id, or a signed double-submit cookie carrying the same session id.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-token-validation)

**Frameworks that enforce CSRF by default do so through a global middleware plus explicit per-view exemptions, so the bypass is not breaking the token scheme - it is finding a view the middleware was told to skip.**

Modern frameworks have made the global-token-missing case rare and pushed the vulnerability into the exemption mechanism. Django's default CsrfViewMiddleware refuses unsafe methods without a token, and csrf_exempt marks a single view as being exempt from the protection the middleware ensures; Django also offers csrf_protect to opt a view back in. Rails does the same by default with default_protect_from_forgery, with protect_from_forgery with: :exception as the manual equivalent. So the productive hunting move is to enumerate the exempt surface rather than to look for absent tokens: legacy AJAX endpoints, webhook receivers, endpoints that were exempted to make a failing integration test pass, and views exempted on the assumption that they are safe because they 'only return data'. The tell in the code and the response is a state-changing view that accepts a cross-site POST and returns success while every neighbouring view returns 403.

- *Disproof:* The claim fails when the exemption is not reachable as a state change - a GET-only view, a view bound to a machine-to-machine credential, or an endpoint whose response body is inert data. It also fails if the middleware is not actually installed on that URL prefix, since many frameworks scope middleware by path, so a view can be unprotected simply because it sits outside the middleware's route list rather than because it carries an exemption marker. And if the exempt endpoint independently requires a header, a content type, or a token of another kind, the exemption does not translate into a CSRF finding. Conversely, an exemption that is applied broadly to a whole controller rather than one action is a real finding, not an artefact.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/ref/csrf/); [guides.rubyonrails.org](https://guides.rubyonrails.org/security.html)

## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Script execution on any sibling domain of the target site defeats SameSite and reads the CSRF token, so one same-site injection converts a hardened CSRF defence into a silent state change on the real origin.**

Both halves are published and they compose into a chain that no single SameSite or token control stops. First, the site-scoped nature of the control is the gap: the difference between a site and an origin is their scope, a site encompasses multiple domain names whereas an origin only includes one, and crucially a cross-origin request can still be same-site, but not the other way around. The consequence is direct, since any vulnerability enabling arbitrary JavaScript execution can be abused to bypass site-based defenses on other domains belonging to the same site. Second, the token is not a defence in that position either, because OWASP states plainly that XSS can defeat all CSRF mitigation techniques. So an attacker with script execution on a sibling host can read the token from the real origin's DOM, or simply issue the state-changing request as a same-site request that carries every cookie, and the request the server sees is one its own defences consider legitimate. The reason this is a chain and not a note on SameSite is that the pre-condition is a different class of bug, on a different host, with a different fix, so a review of the CSRF controls alone will not find it.

- *Disproof:* The site has no sibling domain under the registrable domain, or every sibling is separately trusted and none carries script execution or reflects attacker input, so no attacker-controlled origin is same-site with the target.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
