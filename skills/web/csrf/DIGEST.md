<!-- GENERATED from db/wks.db — do not edit -->
# Cross-Site Request Forgery

> surface: `web` · CWE: CWE-352 · OWASP: A01:2021
> maturity: **mature** — 40 items, 33 supported, 4 FP rules, 1 chains

A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.

**Aliases:** csrf, cross site request forgery, xsrf, csrf token bypass

## Prerequisite

- **CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.**  
  `high_confidence` · score 0.905 · disproved by: Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>
- **A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.**  
  `high_confidence` · score 0.8515 · disproved by: If every request reachable at the endpoint is read-only and produces no state change for the victim, the cross-site request forgery claim is refuted.
  sources: <https://portswigger.net/web-security/csrf> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>

## Technique

- **A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.**  
  `high_confidence` · score 0.9065 · disproved by: If the endpoint rejects every one of those mutations (method switch, removed/blanked/altered token, replayed or attacker-supplied token, Content-Type change, stripped referer) with the same consistent rejection, the anti-forgery control is holding.
  sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>
- **A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.**  
  `high_confidence` · score 0.8965 · disproved by: The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- **A state-changing request replayed from an attacker origin without an anti-CSRF token succeeds when the session cookie carries no effective SameSite restriction.**  
  `high_confidence` · score 0.874 · disproved by: If the browser withholds the session cookie cross-site, or the server rejects the tokenless replay with 4xx and no state change, the CSRF replay does not reproduce.
  sources: <https://bishopfox.com/blog/the-growing-concern-of-api-security> · <https://snyk.io/blog/how-to-protect-node-js-apps-from-csrf-attacks/>
- **Rejecting unsafe methods when Sec-Fetch-Site is cross-site, with a mandatory fallback to Origin verification on browsers that omit the headers, blocks CSRF without any token and no client change.**  
  `high_confidence` · score 0.869 · disproved by: The server accepts unsafe methods with Sec-Fetch-Site: cross-site, or the check is present but there is no Origin/Referer fallback so any client omitting the headers is admitted by default.
  sources: <https://www.w3.org/TR/fetch-metadata/> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- **A GraphQL endpoint that enforces CSRF only on POST is open to state-changing mutations triggered by a self-submitted form with method=GET in a logged-in victim's browser.**  
  `high_confidence` · score 0.8665 · disproved by: Enforce a CSRF token for every HTTP method including GET, or reject GET requests to the GraphQL endpoint entirely.
  sources: <https://portswigger.net/web-security/csrf> · <https://hackerone.com/reports/1122408>
- **A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.**  
  `high_confidence` · score 0.8515 · disproved by: Opening the generated auto-submit page from an origin the target does not trust produces no state change in the victim account, so the page proves nothing.
  sources: <https://portswigger.net/web-security/csrf> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>
- **Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because most CSRF defenses can be bypassed using attacker-controlled script.**  
  `high_confidence` · score 0.8055 · disproved by: Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ensure that the application is free of cross-site scripting issues ( CWE-79 ), b”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- **CMS allows modification of configuration via CSRF attack against the administrator.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CMS allows modification of configuration via CSRF attack against the administrat”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- **web interface allows password changes or stopping a virtual machine via CSRF.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“web interface allows password changes or stopping a virtual machine via CSRF”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>

## Validation

- **A cross-site POST that changes server state while carrying the victim's ambient cookie and no anti-CSRF token proves CSRF rather than a same-origin caller.**  
  `high_confidence` · score 0.984 · disproved by: If the replayed cross-site request is rejected with 401 or 403, or if the state change is absent when compared against the same-origin baseline, then no CSRF exists and the observation is a same-origin authorization control doing its job.
  sources: <https://www.w3.org/TR/fetch-metadata/> · <https://blog.qualys.com/product-tech/2017/01/26/cross-site-request-forgery-what-happened-to-the-sleeping-giant>
- **CSRF is only reportable on an endpoint whose effect survives being reached without the victim's intent, so the decisive evidence is a state change caused by a cross-site request, not a 200 on a hand-rolled POST.**  
  `high_confidence` · score 0.8905 · disproved by: The rule is void when the effect is not observable and not attacker-meaningful - a GET that only increments a counter nobody can read, writes a cache entry, or logs a hit is not a reportable CSRF even though it technically mutates. It also fails if the endpoint's state change requires an anti-CSRF artefact the attacker cannot obtain even cross-site, such as a one-time code delivered out of band. And a cross-origin delivery is not achievable for every endpoint class: a request that requires a preflighted custom header, a non-simple Content-Type, or a fetch with credentials omitted never leaves the attacker page, so 'no cross-origin vector' is a real and reportable negative, not an excuse.
  sources: <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://docs.djangoproject.com/en/5.0/ref/csrf/>

## Fp Rule

- **An API endpoint authenticated only by an Authorization header and no ambient cookie is not CSRF-exploitable, because no cross-origin page can make the browser attach the credential.**  
  `high_confidence` · score 0.9565 · disproved by: A permissive Access-Control-Allow-Origin with Allow-Credentials makes the credential attachable cross-origin, and an API that mirrors the Authorization value into a cookie, or accepts a token in a query string that a cross-site img or form can carry, restores the vector with no cookie present at all.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **A CSRF validation failure that occurs only after a fresh login is token rotation working as designed, not a control failure - the pre-login form legitimately holds a stale token.**  
  `high_confidence` · score 0.8655 · disproved by: The rule is wrong if the failure persists after the page is reloaded post-login, which means the mismatch is structural rather than temporal - a session-rotation bug, a token stored in the session while the form reads a cookie, a per-request mask the server never unmasks, or a multi-tab token cache serving a value from a different session. It is also wrong if the secret does not actually rotate but the failure still correlates with login, which points at a login handler that rewrites the cookie without updating the stored secret. And rotation at login is a genuine weakness in one specific case: an endpoint that accepts the previous secret as well as the current one, so a token captured before the victim's login still validates afterwards.
  sources: <https://docs.djangoproject.com/en/5.0/ref/csrf/> · <https://guides.rubyonrails.org/security.html>
- **An attacker who supplies both halves of a synchroniser-token pair - a CSRF cookie they choose plus a POST field containing the same value - has not demonstrated CSRF, because a cross-origin attacker has no channel to write the victim's cookie.**  
  `high_confidence` · score 0.838 · disproved by: The rule breaks down in two real situations. First, subdomain or sibling-origin cookie injection: if any attacker-reachable host can set a cookie on the parent domain - via a cookie-tossing endpoint, an open redirect onto the parent, a permissive Domain attribute, or XSS on a subdomain - then the attacker does have a channel to plant the cookie half of the pair and the synchroniser token collapses. Second, if the application accepts the token from a header or query parameter that a simple cross-origin request can set, or compares only a substring or a truncated value, the pair is forgeable without cookie write at all. A finding backed by either of those is genuine CSRF despite the pairing.
  sources: <https://docs.djangoproject.com/en/5.0/ref/csrf/> · <https://www.rfc-editor.org/rfc/rfc6265.txt>
- **A CSRF finding against a low-privilege victim is still a real finding; the privileged-role case raises impact but must not be reported as a distinct or additional vulnerability.**  
  `high_confidence` · score 0.833 · disproved by: The endpoint enforces a server-side proof of intentional user action, such as a synchronizer token validated on every unsafe method, a re-authentication challenge, or a same-origin header check with fallback, in which case the role of the victim changes the impact of a compromise but cannot create the forgery.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>

## Evidence

- **The credential half of a CSRF proof is the Set-Cookie header on the login response: when the session cookie carries no SameSite attribute, or SameSite=None, the browser attaches it to the attacker's cross-origin POST automatically, so the forged request arrives pre-authenticated without the attacker ever holding the cookie value.**  
  `high_confidence` · score 0.934 · disproved by: The claim is false when the session cookie is issued SameSite=Strict, or SameSite=Lax on an endpoint that refuses GET and honours no method-override parameter, because the cookie then does not ride along on a cross-origin POST. It is also false where authentication does not ride on an ambient cookie at all - a bearer token the attacker's page cannot read, a per-request signature bound to the body, or a custom header that forces a preflight the server refuses - since no credential is silently attached and there is nothing to forge. A Set-Cookie that is absent entirely, or a cookie the server never checks, does not satisfy the claim either.
  sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie> · <https://www.rfc-editor.org/rfc/rfc6265.html>
- **CSRF is proven when one cross-origin POST to a state-changing endpoint, carrying only the victim's ambient session cookie and no anti-CSRF token, returns the same success status and the same durable side effect as the authenticated same-origin baseline request.**  
  `high_confidence` · score 0.934 · disproved by: The claim is false if the replayed cross-origin request is refused with 401, 403 or 405, if it is answered with a challenge, a one-time code or any interactive confirmation, if the response body differs from the same-origin baseline, or if re-reading the affected object shows no attacker-supplied value persisted. It is also false where no cross-origin delivery is achievable at all - an endpoint that requires a preflighted custom header or a non-simple Content-Type never leaves the attacker page - and false where the state change is not attacker-meaningful, such as a counter nobody can read.
  sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS> · <https://www.rfc-editor.org/rfc/rfc6454.html>
- **A web application that identifies the user only through a session cookie, with no anti-CSRF token, custom request header, or origin check, lets an attacker forge state-changing requests that execute as the victim.**  
  `high_confidence` · score 0.9325 · disproved by: The state-changing endpoint requires a secret, unpredictable CSRF token per session, issues a custom request header the attacker cannot set cross-origin, verifies Origin or Referer against its own domain, or the session cookie is set with SameSite=Strict and no sibling-subdomain bypass is available.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>
- **An endpoint that derives its CSRF decision from the Origin header it receives proves nothing when the header can be made to carry the victim's own origin, because the check and the forgery then agree by construction and the forged request is accepted with a 200 and the state change applied.**  
  `high_confidence` · score 0.918 · disproved by: The claim is false when the server rejects the request whenever Origin is absent or differs from its own host, when the header cannot be reflected or overridden by any reachable path, or when an independent anti-CSRF token is still required. It is likewise false if the forged-Origin request is refused with 403, and false when the endpoint's effect is not attacker-meaningful or is undone before an attacker could use it.
  sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc6454.html>
- **A code change deployed on 2022-02-14 disabled the CSRF protection on all Stripe Dashboard endpoints, letting a cross-site form POST change the victim's email subscription settings without a token; the flaw was fixed on 2022-03-03.**  
  `high_confidence` · score 0.8615 · disproved by: Retain CSRF middleware globally, restrict the disabled actions to non-sensitive operations requiring step-up authentication, or ensure no state-changing action is reachable cross-origin.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://hackerone.com/reports/1483327>

## Impact

- **An OAuth and integrations linking flow with improper CSRF token validation lets an attacker associate the attacker's third-party account with the victim's account with one click, then issue unauthorized calls through the linked integration, achieving account takeover of the linked integration.**  
  `high_confidence` · score 0.8115 · disproved by: Bind the CSRF token to the user and to the specific OAuth callback state, require user interaction to complete consent, and validate the OAuth state parameter.
  sources: <https://portswigger.net/web-security/csrf> · <https://hackerone.com/reports/1727221>

## Variant

- **Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken.**  
  `high_confidence` · score 0.879 · disproved by: A framed load of the endpoint that cannot induce the victim to perform the action shows the framing path does not deliver the cross-site request forgery.
  sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>

## Bypass

- **A CSRF defence that validates the anti-CSRF token only on POST is bypassed by reissuing the identical state change as a GET, because many endpoints accept either method.**  
  `high_confidence` · score 0.96 · disproved by: The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **A CSRF check written as validate-if-present is bypassed by deleting the whole token parameter, because an absent parameter is never compared against the expected value.**  
  `high_confidence` · score 0.93 · disproved by: Deleting the token parameter produces the same rejection status and body as submitting a wrong token, and no state change is committed in either case.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **SameSite=Lax does not fully mitigate CSRF: browsers treat sibling subdomains as same-site, and Chrome applies Lax by default when no SameSite attribute is set and does not enforce it for top-level POSTs for roughly two minutes, so an attacker-controlled subdomain can drive a cross-site POST that carries the same-parent session cookie.**  
  `high_confidence` · score 0.8475 · disproved by: Set SameSite=Strict on the session cookie, isolate the API on a domain with no sibling subdomains sharing the parent, or otherwise defeat the Lax-by-default window.
  sources: <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions> · <https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg>
- **SameSite cookie protection is a site-scoped, not origin-scoped, control, so JavaScript execution on any sibling domain of the same site defeats it completely.**  
  `high_confidence` · score 0.8475 · disproved by: The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- **A CSRF token accepted from a global pool of issued tokens, rather than bound to the requesting session, is defeated by the attacker logging in with their own account and feeding the victim a token the attacker legitimately holds.**  
  `high_confidence` · score 0.8475 · disproved by: A token issued to one session is rejected when presented by a different session, whether compared against a server-side per-session value, an HMAC bound to the session id, or a signed double-submit cookie carrying the same session id.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **Frameworks that enforce CSRF by default do so through a global middleware plus explicit per-view exemptions, so the bypass is not breaking the token scheme - it is finding a view the middleware was told to skip.**  
  `high_confidence` · score 0.838 · disproved by: The claim fails when the exemption is not reachable as a state change - a GET-only view, a view bound to a machine-to-machine credential, or an endpoint whose response body is inert data. It also fails if the middleware is not actually installed on that URL prefix, since many frameworks scope middleware by path, so a view can be unprotected simply because it sits outside the middleware's route list rather than because it carries an exemption marker. And if the exempt endpoint independently requires a header, a content type, or a token of another kind, the exemption does not translate into a CSRF finding. Conversely, an exemption that is applied broadly to a whole controller rather than one action is a real finding, not an artefact.
  sources: <https://docs.djangoproject.com/en/5.0/ref/csrf/> · <https://guides.rubyonrails.org/security.html>
- **A path-traversal routing quirk in the GitHub Enterprise Server management console lets a PUT reach the protected admin endpoint without a valid CSRF token: the router matches the post-traversal path for execution but the pre-traversal path for the CSRF-protection scope.**  
  `high_confidence` · score 0.8065 · disproved by: The router normalizes the path identically for protection scoping and execution, or the target endpoint refuses traversal sequences.
  sources: <https://hackerone.com/reports/1497169> · <https://nvd.nist.gov/vuln/detail/CVE-2022-23732>

## Chain Link

- **SameSite=Lax sibling-subdomain misconfiguration combined with missing Content-Type enforcement on the Argo CD API yields a cross-origin POST that Argo CD treats as same-site and executes without a CSRF token, taking over the Argo CD instance and downstream deployment state.**  
  `high_confidence` · score 0.8475 · disproved by: Enforce Strict SameSite on the API cookie, reject the form-driven content-type gap, or if the attacker has no sibling subdomain on the shared parent, the chain does not execute.
  sources: <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions> · <https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg>
- **Script execution on any sibling domain of the target site defeats SameSite and reads the CSRF token, so one same-site injection converts a hardened CSRF defence into a silent state change on the real origin.**  
  `high_confidence` · score 0.8475 · disproved by: The site has no sibling domain under the registrable domain, or every sibling is separately trusted and none carries script execution or reflects attacker input, so no attacker-controlled origin is same-site with the target.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
