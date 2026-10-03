---
name: csrf-hunting
description: Use when hunting Cross-Site Request Forgery in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Cross-Site Request Forgery — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE CWE-352 · OWASP A01:2021
> evidence: 36 items, 26 supported, 6 FP rules, 1 chains
> maturity: **mature**

A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.

**Also called:** csrf, cross site request forgery, xsrf, csrf token bypass


## Prerequisites (do not start without these)

- A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand. _(unverified)_
  - **Disproof:** If every request reachable at the endpoint is read-only and produces no state change for the victim, the cross-site request forgery claim is refuted.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>
- A cross-site request forgery finding is only actionable if the target exposes a relevant state-changing action; without one there is nothing to forge and the report does not stand.
  - **Disproof:** If every request reachable at the endpoint is read-only and produces no state change for the victim, the cross-site request forgery claim is refuted.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>
- CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.
  - **Disproof:** Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>

## Techniques (what to change)

- Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because most CSRF defenses can be bypassed using attacker-controlled script. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because mos".
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- CMS allows modification of configuration via CSRF attack against the administrator _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CMS allows modification of configuration via CSRF attack against the administrator".
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- web interface allows password changes or stopping a virtual machine via CSRF _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "web interface allows password changes or stopping a virtual machine via CSRF".
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.
  - **Disproof:** The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- Rejecting unsafe methods when Sec-Fetch-Site is cross-site, with a mandatory fallback to Origin verification on browsers that omit the headers, blocks CSRF without any token and no client change.
  - **Disproof:** The server accepts unsafe methods with Sec-Fetch-Site: cross-site, or the check is present but there is no Origin/Referer fallback so any client omitting the headers is admitted by default.
  - Sources: <https://www.w3.org/TR/fetch-metadata/> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded. _(unverified)_
  - **Disproof:** If the endpoint rejects every one of those mutations (method switch, removed/blanked/altered token, replayed or attacker-supplied token, Content-Type change, stripped referer) with the same consistent rejection, the anti-forgery control is holding.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>
- A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin. _(unverified)_
  - **Disproof:** Opening the generated auto-submit page from an origin the target does not trust produces no state change in the victim account, so the page proves nothing.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>
- A hunter can break anti-forgery defences without ever forging a token value, by changing the request shape itself: switching the request method POST to GET, dropping the token parameter, blanking it, replaying an unused valid token, feeding the victim the attacker's own token, matching only the token's length, mutating one character, or switching Content-Type to a multipart form instead of json/x-www-form-urlencoded.
  - **Disproof:** If the endpoint rejects every one of those mutations (method switch, removed/blanked/altered token, replayed or attacker-supplied token, Content-Type change, stripped referer) with the same consistent rejection, the anti-forgery control is holding.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>
- A cross-site request forgery proof-of-concept can be a standalone auto-submitting HTML form placed on an attacker page, so the evidence reproduces with no session scripting and shows the forged request originates cross-origin.
  - **Disproof:** Opening the generated auto-submit page from an origin the target does not trust produces no state change in the victim account, so the page proves nothing.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/csrf.md>
- A state-changing request replayed from an attacker origin without an anti-CSRF token succeeds when the session cookie carries no effective SameSite restriction.
  - **Disproof:** If the browser withholds the session cookie cross-site, or the server rejects the tokenless replay with 4xx and no state change, the CSRF replay does not reproduce.
  - Sources: <https://bishopfox.com/blog/the-growing-concern-of-api-security> · <https://snyk.io/blog/how-to-protect-node-js-apps-from-csrf-attacks/>

## Tests

- To decide this case, observe: Discard the finding when the auth cookie you captured in the replay carries SameSite=Strict or SameSite=Lax, or the Set-Cookie on login sets it without a SameSite=None; Secure pair, because the browser then has no credential to attach to the forged request and the forged request is anonymous. _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (csrf.fprule.samesite_cookie_blocks_cross_site_credential) states the full boundary.
  - Sources: <https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Validation bar (how to prove it)

- CSRF is only reportable on an endpoint whose effect survives being reached without the victim's intent, so the decisive evidence is a state change caused by a cross-site request, not a 200 on a hand-rolled POST.
  - **Disproof:** The rule is void when the effect is not observable and not attacker-meaningful - a GET that only increments a counter nobody can read, writes a cache entry, or logs a hit is not a reportable CSRF even though it technically mutates. It also fails if the endpoint's state change requires an anti-CSRF artefact the attacker cannot obtain even cross-site, such as a one-time code delivered out of band. And a cross-origin delivery is not achievable for every endpoint class: a request that requires a preflighted custom header, a non-simple Content-Type, or a fetch with credentials omitted never leaves the attacker page, so 'no cross-origin vector' is a real and reportable negative, not an excuse.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://docs.djangoproject.com/en/5.0/ref/csrf/>
- A cross-site POST that changes server state while carrying the victim's ambient cookie and no anti-CSRF token proves CSRF rather than a same-origin caller.
  - **Disproof:** If the replayed cross-site request is rejected with 401 or 403, or if the state change is absent when compared against the same-origin baseline, then no CSRF exists and the observation is a same-origin authorization control doing its job.
  - Sources: <https://www.w3.org/TR/fetch-metadata/> · <https://blog.qualys.com/product-tech/2017/01/26/cross-site-request-forgery-what-happened-to-the-sleeping-giant>

## False-positive rules (when to reject it)

- A CSRF validation failure that occurs only after a fresh login is token rotation working as designed, not a control failure - the pre-login form legitimately holds a stale token.
  - **Disproof:** The rule is wrong if the failure persists after the page is reloaded post-login, which means the mismatch is structural rather than temporal - a session-rotation bug, a token stored in the session while the form reads a cookie, a per-request mask the server never unmasks, or a multi-tab token cache serving a value from a different session. It is also wrong if the secret does not actually rotate but the failure still correlates with login, which points at a login handler that rewrites the cookie without updating the stored secret. And rotation at login is a genuine weakness in one specific case: an endpoint that accepts the previous secret as well as the current one, so a token captured before the victim's login still validates afterwards.
  - Sources: <https://docs.djangoproject.com/en/5.0/ref/csrf/> · <https://guides.rubyonrails.org/security.html>
- An endpoint that answers only safe methods (GET/HEAD) and only reads state is not a CSRF finding for having no anti-CSRF token: the CSRF precondition is that the victim sends a request that triggers a state change, and a GET that changes nothing cannot be ridden.
  - **Disproof:** It IS CSRF if the same GET (a) mutates state - deletes, archives, toggles, subscribes, confirms, transfers - (b) triggers a state change through a redirect or JS handler the GET returns, or (c) the endpoint accepts POST as an alias for the same action. Prove it by replaying the cross-site GET with a victim cookie and observing a server-side state delta, not by reading the HTML form for a token.
  - Sources: <https://capec.mitre.org/data/definitions/62.html> · <https://www.zaproxy.org/docs/alerts/10202/>
- A CSRF finding against a low-privilege victim is still a real finding; the privileged-role case raises impact but must not be reported as a distinct or additional vulnerability.
  - **Disproof:** The endpoint enforces a server-side proof of intentional user action, such as a synchronizer token validated on every unsafe method, a re-authentication challenge, or a same-origin header check with fallback, in which case the role of the victim changes the impact of a compromise but cannot create the forgery.
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>
- An attacker who supplies both halves of a synchroniser-token pair - a CSRF cookie they choose plus a POST field containing the same value - has not demonstrated CSRF, because a cross-origin attacker has no channel to write the victim's cookie.
  - **Disproof:** The rule breaks down in two real situations. First, subdomain or sibling-origin cookie injection: if any attacker-reachable host can set a cookie on the parent domain - via a cookie-tossing endpoint, an open redirect onto the parent, a permissive Domain attribute, or XSS on a subdomain - then the attacker does have a channel to plant the cookie half of the pair and the synchroniser token collapses. Second, if the application accepts the token from a header or query parameter that a simple cross-origin request can set, or compares only a substring or a truncated value, the pair is forgeable without cookie write at all. A finding backed by either of those is genuine CSRF despite the pairing.
  - Sources: <https://docs.djangoproject.com/en/5.0/ref/csrf/> · <https://www.rfc-editor.org/rfc/rfc6265.txt>
- An API endpoint authenticated only by an Authorization header and no ambient cookie is not CSRF-exploitable, because no cross-origin page can make the browser attach the credential.
  - **Disproof:** A permissive Access-Control-Allow-Origin with Allow-Credentials makes the credential attachable cross-origin, and an API that mirrors the Authorization value into a cookie, or accepts a token in a query string that a cross-site img or form can carry, restores the vector with no cookie present at all.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- A state-changing POST that succeeds from an attacker page is not CSRF when the session cookie is SameSite=Strict or SameSite=Lax, because the browser withholds it on cross-site subresource requests.
  - **Disproof:** A SameSite=Lax cookie is still sent on a cross-site top-level GET navigation, so any state change reachable by GET, or any endpoint that also honours a cookie-less cross-site POST because the session is re-established from another channel, is genuinely exploitable despite the attribute.
  - Sources: <https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Evidence requirements

- A cross-origin write shaped like an HTML form submission is delivered by the browser with no CORS preflight and no Access-Control-Allow-Origin opt-in from the target, so a 200 on that request is a same-origin action taken on the victim's behalf, not a read the browser blocked. _(unverified)_
  - **Disproof:** The claim is false when the request is in fact preflighted - a custom header, a non-simple Content-Type such as application/json, or a DELETE - and the server's OPTIONS response withholds the Access-Control-Allow-Origin value, in which case the browser never sends the write and no state change is reachable cross-origin. It is also false when the endpoint validates an anti-CSRF token, a custom header or the Origin value, and false when the durable effect is not attacker-meaningful.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS>
- An endpoint that derives its CSRF decision from the Origin header it receives proves nothing when the header can be made to carry the victim's own origin, because the check and the forgery then agree by construction and the forged request is accepted with a 200 and the state change applied.
  - **Disproof:** The claim is false when the server rejects the request whenever Origin is absent or differs from its own host, when the header cannot be reflected or overridden by any reachable path, or when an independent anti-CSRF token is still required. It is likewise false if the forged-Origin request is refused with 403, and false when the endpoint's effect is not attacker-meaningful or is undone before an attacker could use it.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc6454.html>
- The credential half of a CSRF proof is the Set-Cookie header on the login response: when the session cookie carries no SameSite attribute, or SameSite=None, the browser attaches it to the attacker's cross-origin POST automatically, so the forged request arrives pre-authenticated without the attacker ever holding the cookie value.
  - **Disproof:** The claim is false when the session cookie is issued SameSite=Strict, or SameSite=Lax on an endpoint that refuses GET and honours no method-override parameter, because the cookie then does not ride along on a cross-origin POST. It is also false where authentication does not ride on an ambient cookie at all - a bearer token the attacker's page cannot read, a per-request signature bound to the body, or a custom header that forces a preflight the server refuses - since no credential is silently attached and there is nothing to forge. A Set-Cookie that is absent entirely, or a cookie the server never checks, does not satisfy the claim either.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie> · <https://www.rfc-editor.org/rfc/rfc6265.html>
- CSRF is proven when one cross-origin POST to a state-changing endpoint, carrying only the victim's ambient session cookie and no anti-CSRF token, returns the same success status and the same durable side effect as the authenticated same-origin baseline request.
  - **Disproof:** The claim is false if the replayed cross-origin request is refused with 401, 403 or 405, if it is answered with a challenge, a one-time code or any interactive confirmation, if the response body differs from the same-origin baseline, or if re-reading the affected object shows no attacker-supplied value persisted. It is also false where no cross-origin delivery is achievable at all - an endpoint that requires a preflighted custom header or a non-simple Content-Type never leaves the attacker page - and false where the state change is not attacker-meaningful, such as a counter nobody can read.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS> · <https://www.rfc-editor.org/rfc/rfc6454.html>

## Variants

- Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken. _(unverified)_
  - **Disproof:** A framed load of the endpoint that cannot induce the victim to perform the action shows the framing path does not deliver the cross-site request forgery.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>
- Where an endpoint's page is itself clickjacking-vulnerable, the same state change can be driven by framing the page, which makes the anti-forgery token irrelevant rather than broken.
  - **Disproof:** A framed load of the endpoint that cannot induce the victim to perform the action shows the framing path does not deliver the cross-site request forgery.
  - Sources: <https://cwe.mitre.org/data/definitions/1275.html> · <https://www.rfc-editor.org/rfc/rfc9110.txt> · <https://kathan19.gitbook.io/howtohunt/csrf/cross_site_request_forgery_bypass.md>

## Defence bypasses

- Frameworks that enforce CSRF by default do so through a global middleware plus explicit per-view exemptions, so the bypass is not breaking the token scheme - it is finding a view the middleware was told to skip.
  - **Disproof:** The claim fails when the exemption is not reachable as a state change - a GET-only view, a view bound to a machine-to-machine credential, or an endpoint whose response body is inert data. It also fails if the middleware is not actually installed on that URL prefix, since many frameworks scope middleware by path, so a view can be unprotected simply because it sits outside the middleware's route list rather than because it carries an exemption marker. And if the exempt endpoint independently requires a header, a content type, or a token of another kind, the exemption does not translate into a CSRF finding. Conversely, an exemption that is applied broadly to a whole controller rather than one action is a real finding, not an artefact.
  - Sources: <https://docs.djangoproject.com/en/5.0/ref/csrf/> · <https://guides.rubyonrails.org/security.html>
- The naive double-submit cookie pattern is bypassable by any actor able to write a cookie on the target domain, which a vulnerable sibling subdomain, a DNS takeover, or plaintext-HTTP injection onto a non-__Host- cookie all provide. _(unverified)_
  - **Disproof:** The double-submit cookie is signed with a server secret and bound to the session id, is prefixed __Host- so it cannot be overwritten from a sibling or over plaintext HTTP, and the server additionally requires the value in a custom header or form parameter rather than trusting the cookie.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- SameSite=Lax still attaches the session cookie to a top-level GET navigation, so a server that accepts a form submission over GET, or honours a framework method-override parameter, reopens CSRF despite SameSite being set.
  - **Disproof:** The endpoint refuses GET with 405 regardless of any override parameter, honours no framework method override, or the session cookie is SameSite=Strict so a top-level cross-site navigation does not carry it.
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- SameSite cookie protection is a site-scoped, not origin-scoped, control, so JavaScript execution on any sibling domain of the same site defeats it completely.
  - **Disproof:** The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- A CSRF token accepted from a global pool of issued tokens, rather than bound to the requesting session, is defeated by the attacker logging in with their own account and feeding the victim a token the attacker legitimately holds.
  - **Disproof:** A token issued to one session is rejected when presented by a different session, whether compared against a server-side per-session value, an HMAC bound to the session id, or a signed double-submit cookie carrying the same session id.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- A CSRF check written as validate-if-present is bypassed by deleting the whole token parameter, because an absent parameter is never compared against the expected value.
  - **Disproof:** Deleting the token parameter produces the same rejection status and body as submitting a wrong token, and no state change is committed in either case.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- A CSRF defence that validates the anti-CSRF token only on POST is bypassed by reissuing the identical state change as a GET, because many endpoints accept either method.
  - **Disproof:** The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.
  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>

## Chaining opportunities

- Script execution on any sibling domain of the target site defeats SameSite and reads the CSRF token, so one same-site injection converts a hardened CSRF defence into a silent state change on the real origin.
  - **Disproof:** The site has no sibling domain under the registrable domain, or every sibling is separately trusted and none carries script execution or reflects attacker input, so no attacker-controlled origin is same-site with the target.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>

---
Full class document: `domains/web/csrf/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id csrf`
