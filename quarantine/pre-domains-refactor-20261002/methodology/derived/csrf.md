# Methodology — Cross-Site Request Forgery

> Derived from 19 verified items. Regenerate with `python -m wks.methodgen --class csrf --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A state-changing request is accepted from another origin because the server never proves the request was intentionally initiated.

**References.** CWE-352 · A01:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**CSRF is exploitable only when all three conditions hold together: a relevant attacker-interesting action, session identification relying only on cookies the browser auto-attaches, and no unpredictable request parameter the attacker would have to know.**

PortSwigger states three conditions must be in place for a CSRF attack to be possible: a relevant action (privileged, such as modifying permissions for other users, or any action on user-specific data such as changing the user's own password); cookie-based session handling, where the application relies solely on session cookies to identify the user and there is no other mechanism for tracking sessions or validating requests; and no unpredictable request parameters, meaning the requests that perform the action contain no parameters whose values the attacker cannot determine or guess. The password-change example makes the third condition concrete: the function is not vulnerable if the attacker needs to know the value of the existing password. Triage use: a state-changing POST protected by a re-typed password fails condition three and is not a CSRF finding, no matter what the cookies do. Testing a CSRF candidate means establishing all three, not one.

- *Disproof:* Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [portswigger.net](https://portswigger.net/web-security/csrf)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ensure that the application is free of cross-site scripting issues ( CWE-79 ), because mos".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [owasp.org](https://owasp.org/www-community/attacks/csrf)

**CMS allows modification of configuration via CSRF attack against the administrator**

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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CMS allows modification of configuration via CSRF attack against the administrator".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [owasp.org](https://owasp.org/www-community/attacks/csrf)

**web interface allows password changes or stopping a virtual machine via CSRF**

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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "web interface allows password changes or stopping a virtual machine via CSRF".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/352.html); [owasp.org](https://owasp.org/www-community/attacks/csrf)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A cross-site POST that changes server state while carrying the victim's ambient cookie and no anti-CSRF token proves CSRF rather than a same-origin caller.**

Step: replay the victim's state-changing request as a bare form POST from an attacker origin, with no custom request header and no token parameter, and record the response status against a baseline captured with the same cookie sent as a same-origin client request. The claim is proven by the differential, not by the 200: the cross-site request produces the same state change and the same response as the same-origin one, and a second read of the affected resource shows the change persisted. The absence of the token from the replayed request is the observation that separates this from an authorization failure, because a request that is rejected unauthenticated never reaches the state-changing code. Note that ambient credentials alone make this reachable, so the precondition is a cookie the browser attaches automatically.

- *Disproof:* If the replayed cross-site request is rejected with 401 or 403, or if the state change is absent when compared against the same-origin baseline, then no CSRF exists and the observation is a same-origin authorization control doing its job.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/product-tech/2017/01/26/cross-site-request-forgery-what-happened-to-the-sleeping-giant); [w3.org](https://www.w3.org/TR/fetch-metadata/)

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

**The naive double-submit cookie pattern is bypassable by any actor able to write a cookie on the target domain, which a vulnerable sibling subdomain, a DNS takeover, or plaintext-HTTP injection onto a non-__Host- cookie all provide.**

OWASP now marks the pattern with an explicit warning: the Naive Double-Submit Cookie pattern is bypassable by an attacker who can write cookies on the target domain, e.g. via a vulnerable sibling subdomain, DNS takeover, or plaintext-HTTP cookie injection on a non-__Host- cookie, and for new code the Signed Double-Submit pattern should be used instead. PortSwigger gives the mechanism from the attacker's side: the cookie-setting behaviour does not even need to exist within the same web application as the CSRF vulnerability, since any other application within the same DNS domain can potentially be leveraged to set cookies in the targeted application if the controlled cookie has suitable scope, with the example of a cookie-setting function on staging.demo.normal-website.com placing a cookie submitted to secure.normal-website.com. The naive pattern also validates the cookie value rather than an explicit client submission, which is exactly the property an attacker with cookie-write access can satisfy.

- *Disproof:* The double-submit cookie is signed with a server secret and bound to the session id, is prefixed __Host- so it cannot be overwritten from a sibling or over plaintext HTTP, and the server additionally requires the value in a custom header or form parameter rather than trusting the cookie.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/csrf/bypassing-token-validation)

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
