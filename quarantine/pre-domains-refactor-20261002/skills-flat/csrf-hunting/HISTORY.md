# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 12:21 — 70 diff lines
- items: 15 (supported 15), FP rules 4, chains 0, state researching
- still missing: chain

```diff
--- csrf@current
+++ csrf@new
@@ -10,16 +10,28 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-352 · OWASP A01:2021
-> evidence: 5 items, 5 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: items, chain
+> evidence: 15 items, 15 supported, 4 FP rules, 0 chains
+> maturity: **researching** — missing: chain
 
 A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.
 
 **Also called:** csrf, cross site request forgery, xsrf, csrf token bypass
 
 
+## Prerequisites (do not start without these)
+
+- CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.
+  - **Disproof:** Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>
+
 ## Techniques (what to change)
 
+- A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.
+  - **Disproof:** The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
+- Rejecting unsafe methods when Sec-Fetch-Site is cross-site, with a mandatory fallback to Origin verification on browsers that omit the headers, blocks CSRF without any token and no client change.
+  - **Disproof:** The server accepts unsafe methods with Sec-Fetch-Site: cross-site, or the check is present but there is no Origin/Referer fallback so any client omitting the headers is admitted by default.
+  - Sources: <https://www.w3.org/TR/fetch-metadata/> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
 - A state-changing request replayed from an attacker origin without an anti-CSRF token succeeds when the session cookie carries no effective SameSite restriction.
   - **Disproof:** If the browser withholds the session cookie cross-site, or the server rejects the tokenless replay with 4xx and no state change, the CSRF replay does not reproduce.
   - Sources: <https://bishopfox.com/blog/the-growing-concern-of-api-security> · <https://snyk.io/blog/how-to-protect-node-js-apps-from-csrf-attacks/>
@@ -35,6 +47,9 @@
 - An endpoint that answers only safe methods (GET/HEAD) and only reads state is not a CSRF finding for having no anti-CSRF token: the CSRF precondition is that the victim sends a request that triggers a state change, and a GET that changes nothing cannot be ridden.
   - **Disproof:** It IS CSRF if the same GET (a) mutates state - deletes, archives, toggles, subscribes, confirms, transfers - (b) triggers a state change through a redirect or JS handler the GET returns, or (c) the endpoint accepts POST as an alias for the same action. Prove it by replaying the cross-site GET with a victim cookie and observing a server-side state delta, not by reading the HTML form for a token.
   - Sources: <https://capec.mitre.org/data/definitions/62.html> · <https://www.zaproxy.org/docs/alerts/10202/>
+- A CSRF finding against a low-privilege victim is still a real finding; the privileged-role case raises impact but must not be reported as a distinct or additional vulnerability.
+  - **Disproof:** The endpoint enforces a server-side proof of intentional user action, such as a synchronizer token validated on every unsafe method, a re-authentication challenge, or a same-origin header check with fallback, in which case the role of the victim changes the impact of a compromise but cannot create the forgery.
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf>
 - An API endpoint authenticated only by an Authorization header and no ambient cookie is not CSRF-exploitable, because no cross-origin page can make the browser attach the credential.
   - **Disproof:** A permissive Access-Control-Allow-Origin with Allow-Credentials makes the credential attachable cross-origin, and an API that mirrors the Authorization value into a cookie, or accepts a token in a query string that a cross-site img or form can carry, restores the vector with no cookie present at all.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
@@ -42,5 +57,26 @@
   - **Disproof:** A SameSite=Lax cookie is still sent on a cross-site top-level GET navigation, so any state change reachable by GET, or any endpoint that also honours a cookie-less cross-site POST because the session is re-established from another channel, is genuinely exploitable despite the attribute.
   - Sources: <https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
+## Defence bypasses
+
+- The naive double-submit cookie pattern is bypassable by any actor able to write a cookie on the target domain, which a vulnerable sibling subdomain, a DNS takeover, or plaintext-HTTP injection onto a non-__Host- cookie all provide.
+  - **Disproof:** The double-submit cookie is signed with a server secret and bound to the session id, is prefixed __Host- so it cannot be overwritten from a sibling or over plaintext HTTP, and the server additionally requires the value in a custom header or form parameter rather than trusting the cookie.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
+- SameSite=Lax still attaches the session cookie to a top-level GET navigation, so a server that accepts a form submission over GET, or honours a framework method-override parameter, reopens CSRF despite SameSite being set.
+  - **Disproof:** The endpoint refuses GET with 405 regardless of any override parameter, honours no framework method override, or the session cookie is SameSite=Strict so a top-level cross-site navigation does not carry it.
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
+- SameSite cookie protection is a site-scoped, not origin-scoped, control, so JavaScript execution on any sibling domain of the same site defeats it completely.
+  - **Disproof:** The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
+- A CSRF token accepted from a global pool of issued tokens, rather than bound to the requesting session, is defeated by the attacker logging in with their own account and feeding the victim a token the attacker legitimately holds.
+  - **Disproof:** A token issued to one session is rejected when presented by a different session, whether compared against a server-side per-session value, an HMAC bound to the session id, or a signed double-submit cookie carrying the same session id.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
+- A CSRF check written as validate-if-present is bypassed by deleting the whole token parameter, because an absent parameter is never compared against the expected value.
+  - **Disproof:** Deleting the token parameter produces the same rejection status and body as submitting a wrong token, and no state change is committed in either case.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
+- A CSRF defence that validates the anti-CSRF token only on POST is bypassed by reissuing the identical state change as a GET, because many endpoints accept either method.
+  - **Disproof:** The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
+
 ---
 Full class document: `classes/csrf.md` · retrieve more with `python -m wks.cli search "<query>" --class-id csrf`
```

## 2026-10-02 13:38 — 42 diff lines
- items: 19 (supported 19), FP rules 4, chains 1, state mature

```diff
--- csrf@current
+++ csrf@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-352 · OWASP A01:2021
-> evidence: 15 items, 15 supported, 4 FP rules, 0 chains
-> maturity: **researching** — missing: chain
+> evidence: 19 items, 19 supported, 4 FP rules, 1 chains
+> maturity: **mature**
 
 A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.
 
@@ -26,6 +26,15 @@
 
 ## Techniques (what to change)
 
+- Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because most CSRF defenses can be bypassed using attacker-controlled script.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because mos".
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
+- CMS allows modification of configuration via CSRF attack against the administrator
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CMS allows modification of configuration via CSRF attack against the administrator".
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
+- web interface allows password changes or stopping a virtual machine via CSRF
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "web interface allows password changes or stopping a virtual machine via CSRF".
+  - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://owasp.org/www-community/attacks/csrf>
 - A WebSocket handshake that relies on the session cookie is a CSRF target, so cross-site WebSocket hijacking is the same request-forgery class aimed at a different handshake.
   - **Disproof:** The server rejects the upgrade when the Origin is not on an allowlist, or requires a per-connection token in the query or subprotocol that the attacker's page cannot read.
   - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
@@ -78,5 +87,11 @@
   - **Disproof:** The endpoint rejects every method other than POST or PUT with 405, or a GET to the path returns 404/405 without performing the state change, or the token is validated on all methods regardless of verb.
   - Sources: <https://cwe.mitre.org/data/definitions/352.html> · <https://portswigger.net/web-security/csrf/bypassing-token-validation>
 
+## Chaining opportunities
+
+- Script execution on any sibling domain of the target site defeats SameSite and reads the CSRF token, so one same-site injection converts a hardened CSRF defence into a silent state change on the real origin.
+  - **Disproof:** The site has no sibling domain under the registrable domain, or every sibling is separately trusted and none carries script execution or reflects attacker input, so no attacker-controlled origin is same-site with the target.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions>
+
 ---
-Full class document: `classes/csrf.md` · retrieve more with `python -m wks.cli search "<query>" --class-id csrf`
+Full class document: `skills/Web/csrf/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id csrf`
```
