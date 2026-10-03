# Cross-Site Request Forgery

> surface: `web` · CWE: CWE-352 · OWASP: A01:2021
> maturity: **mature** — 19 items, 19 supported, 4 FP rules, 1 chains

A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.

**Aliases:** csrf, cross site request forgery, xsrf, csrf token bypass

## Prerequisite

- **CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.**  
  `high_confidence` · score 0.905 · disproved by: Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>

## Technique

- **A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.**  
  `high_confidence` · score 0.8965 · disproved by: The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- **A state-changing request replayed from an attacker origin without an anti-CSRF token succeeds when the session cookie carries no effective SameSite restriction.**  
  `high_confidence` · score 0.874 · disproved by: If the browser withholds the session cookie cross-site, or the server rejects the tokenless replay with 4xx and no state change, the CSRF replay does not reproduce.
  sources: <https://bishopfox.com/blog/the-growing-concern-of-api-security> · <https://snyk.io/blog/how-to-protect-node-js-apps-from-csrf-attacks/>
- **Rejecting unsafe methods when Sec-Fetch-Site is cross-site, with a mandatory fallback to Origin verification on browsers that omit the headers, blocks CSRF without any token and no client change.**  
  `high_confidence` · score 0.869 · disproved by: The server accepts unsafe methods with Sec-Fetch-Site: cross-site, or the check is present but there is no Origin/Referer fallback so any client omitting the headers is admitted by default.
  sources: <https://www.w3.org/TR/fetch-metadata/> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- **Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because most CSRF defenses can be bypassed using attacker-controlled script.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because mos".
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- **CMS allows modification of configuration via CSRF attack against the administrator**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CMS allows modification of configuration via CSRF attack against the administrator".
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
- **web interface allows password changes or stopping a virtual machine via CSRF**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "web interface allows password changes or stopping a virtual machine via CSRF".
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>

## Validation

- **A cross-site POST that changes server state while carrying the victim's ambient cookie and no anti-CSRF token proves CSRF rather than a same-origin caller.**  
  `high_confidence` · score 0.984 · disproved by: If the replayed cross-site request is rejected with 401 or 403, or if the state change is absent when compared against the same-origin baseline, then no CSRF exists and the observation is a same-origin authorization control doing its job.
  sources: <https://www.w3.org/TR/fetch-metadata/> · <https://blog.qualys.com/product-tech/2017/01/26/cross-site-request-forgery-what-happened-to-the-sleeping-giant>

## Fp Rule

- **An API endpoint authenticated only by an Authorization header and no ambient cookie is not CSRF-exploitable, because no cross-origin page can make the browser attach the credential.**  
  `high_confidence` · score 0.9565 · disproved by: A permissive Access-Control-Allow-Origin with Allow-Credentials makes the credential attachable cross-origin, and an API that mirrors the Authorization value into a cookie, or accepts a token in a query string that a cross-site img or form can carry, restores the vector with no cookie present at all.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **An endpoint that answers only safe methods (GET/HEAD) and only reads state is not a CSRF finding for having no anti-CSRF token: the CSRF precondition is that the victim sends a request that triggers a state change, and a GET that changes nothing cannot be ridden.**  
  `high_confidence` · score 0.924 · disproved by: It IS CSRF if the same GET (a) mutates state - deletes, archives, toggles, subscribes, confirms, transfers - (b) triggers a state change through a redirect or JS handler the GET returns, or (c) the endpoint accepts POST as an alias for the same action. Prove it by replaying the cross-site GET with a victim cookie and observing a server-side state delta, not by reading the HTML form for a token.
  sources: <https://capec.mitre.org/data/definitions/62.html> · <https://www.zaproxy.org/docs/alerts/10202/>
- **A state-changing POST that succeeds from an attacker page is not CSRF when the session cookie is SameSite=Strict or SameSite=Lax, because the browser withholds it on cross-site subresource requests.**  
  `high_confidence` · score 0.899 · disproved by: A SameSite=Lax cookie is still sent on a cross-site top-level GET navigation, so any state change reachable by GET, or any endpoint that also honours a cookie-less cross-site POST because the session is re-established from another channel, is genuinely exploitable despite the attribute.
  sources: <https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **A CSRF finding against a low-privilege victim is still a real finding; the privileged-role case raises impact but must not be reported as a distinct or additional vulnerability.**  
  `high_confidence` · score 0.833 · disproved by: The endpoint enforces a server-side proof of intentional user action, such as a synchronizer token validated on every unsafe method, a re-authentication challenge, or a same-origin header check with fallback, in which case the role of the victim changes the impact of a compromise but cannot create the forgery.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>

## Bypass

- **A CSRF defence that validates the anti-CSRF token only on POST is bypassed by reissuing the identical state change as a GET, because many endpoints accept either method.**  
  `high_confidence` · score 0.96 · disproved by: The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **SameSite=Lax still attaches the session cookie to a top-level GET navigation, so a server that accepts a form submission over GET, or honours a framework method-override parameter, reopens CSRF despite SameSite being set.**  
  `high_confidence` · score 0.9325 · disproved by: The endpoint refuses GET with 405 regardless of any override parameter, honours no framework method override, or the session cookie is SameSite=Strict so a top-level cross-site navigation does not carry it.
  sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- **A CSRF check written as validate-if-present is bypassed by deleting the whole token parameter, because an absent parameter is never compared against the expected value.**  
  `high_confidence` · score 0.93 · disproved by: Deleting the token parameter produces the same rejection status and body as submitting a wrong token, and no state change is committed in either case.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **SameSite cookie protection is a site-scoped, not origin-scoped, control, so JavaScript execution on any sibling domain of the same site defeats it completely.**  
  `high_confidence` · score 0.8475 · disproved by: The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
- **A CSRF token accepted from a global pool of issued tokens, rather than bound to the requesting session, is defeated by the attacker logging in with their own account and feeding the victim a token the attacker legitimately holds.**  
  `high_confidence` · score 0.8475 · disproved by: A token issued to one session is rejected when presented by a different session, whether compared against a server-side per-session value, an HMAC bound to the session id, or a signed double-submit cookie carrying the same session id.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
- **The naive double-submit cookie pattern is bypassable by any actor able to write a cookie on the target domain, which a vulnerable sibling subdomain, a DNS takeover, or plaintext-HTTP injection onto a non-__Host- cookie all provide.**  
  `high_confidence` · score 0.784 · disproved by: The double-submit cookie is signed with a server secret and bound to the session id, is prefixed __Host- so it cannot be overwritten from a sibling or over plaintext HTTP, and the server additionally requires the value in a custom header or form parameter rather than trusting the cookie.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>

## Chain Link

- **Script execution on any sibling domain of the target site defeats SameSite and reads the CSRF token, so one same-site injection converts a hardened CSRF defence into a silent state change on the real origin.**  
  `high_confidence` · score 0.8475 · disproved by: The site has no sibling domain under the registrable domain, or every sibling is separately trusted and none carries script execution or reflects attacker input, so no attacker-controlled origin is same-site with the target.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
