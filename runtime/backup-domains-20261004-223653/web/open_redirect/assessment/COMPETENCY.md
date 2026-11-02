# Methodology — Open Redirect

> Derived from 26 verified items. Regenerate with `python -m wks.methodgen --class open_redirect --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A redirect target is not constrained to a trusted destination.

**References.** CWE-601 · A01:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An open redirect is only present when user-supplied input reaches the destination of a redirect without validation, as distinct from any redirect that exists.**

Replay login, logout, return and language-switch endpoints with a decoy destination parameter and read the resulting Location header. The signal is a Location pointing at your controlled host in response to attacker input. A redirect that ignores the parameter, or that only ever targets fixed in-application routes, is not the vulnerability class even though a 302 is present.

- *Disproof:* If no supplied parameter alters the Location host, or the destination is always a fixed internal route, there is no open redirect to pursue.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory); [snyk.io](https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.**

When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.

HackTricks reference: find openredirect trick (https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md)

- *Disproof:* The redirect parameter refuses external hosts or ignores off-site values and always resolves to a fixed internal path.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc7231.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md); [snyk.io](https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.**

Send an absolute URL to your own collector as the destination parameter and capture the exact Location header returned. Then test whether validation is a real allowlist or a naive check by trying a near-miss host such as the trusted domain prefixed onto your collector. If the near-miss is accepted, the destination check is bypassable and the finding is confirmed at the bypass level.

- *Disproof:* If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications); [snyk.io](https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/)

**An open redirect is proved by a 3xx response whose Location header resolves to an attacker-controlled origin, captured with the redirect not followed; the presence of a `next`, `returnUrl` or `redirect` parameter on a request that returned 200 proves nothing.**

Mechanism: An open redirect is proved by a 3xx response whose Location header resolves to an attacker-controlled origin, captured with the redirect not followed; the presence of a `next`, `returnUrl` or `redirect` parameter on a request that returned 200 proves nothing. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the response cannot be observed with its headers intact — a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured to follow redirects — in which case the Location must be captured from a raw exchange or from the browser's network log, and a screenshot of the final page is insufficient evidence.

- *Disproof:* The claim is false when the response cannot be observed with its headers intact — a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured to follow redirects — in which case the Location must be captured from a raw exchange or from the browser's network log, and a screenshot of the final page is insufficient evidence.
- *Evidence:* high_confidence — [developers.google.com](https://developers.google.com/identity/protocols/oauth2/web-server); [expressjs.com](https://expressjs.com/en/advanced/best-practice-security.html)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.**

The observation is a request to a first-party-looking Microsoft or Google authorize URL that returns a 302 to an attacker domain, which scans as a textbook open redirect on a trusted host. A distinct class of redirection abuse puts the redirection target URL in the OAuth provider's framework: the third-party application registration, where no validation of that URL is applied by the application, and the redirection target URL will be missing from the legitimate URL. The detection that fires is therefore on the identity provider's redirect endpoint, but the controllable value lives in the tenant's consent record for a specific client id, not in any parameter the web application hands to the browser. The benign explanation is that the tenant's administrators or a sanctioned integration registered that client with that redirect_uri. The distinguishing test is attribution: replay the same redirect chain while substituting a client id the tenant never registered, or one registered with a different redirect_uri. If the arbitrary destination only ever appears for a known client id, it is a tenant configuration review item (a malicious or over-permissive app consent), not a web application redirect flaw to be fixed in code.

- *Disproof:* The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
- *Evidence:* high_confidence — [proofpoint.com](https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178)

**A 3xx response whose Location value is a relative reference (/login, ~/folder/Login.aspx, ../dashboard) or an absolute URL on the request's own origin is not an open redirect, because URL resolution against the current base keeps the navigation on the same origin, so no untrusted site ever receives the victim.**

Mechanism: per URL resolution, a Location value without a scheme and authority inherits both from the request URL, so /login and ~/folder/Login.aspx as emitted by sendRedirect/header('Location: ...')/Response.Redirect stay on the reporting host; the code, not the parameter, decides the destination host. The distinguishing check is to resolve the observed Location value against the request URL and compare the resulting scheme+host+port with the request's own: equal means no cross-origin navigation, so the phishing precondition in CWE-601 (user is redirected to an untrusted page while the visible link still shows the trusted name) is absent. Triage: request the endpoint with url=https://evil.example and with url=//evil.example and watch the effective request target in the network log — if the browser resolves both to the reporting origin's host (or the server replaces them with a fixed in-code URL), the finding is a false positive for open redirect and should be re-filed, if anything, as unvalidated input reaching a header sink.

- *Disproof:* The rule fails if the resolved value's authority differs from the request origin in any way the browser honours: a protocol-relative //evil.example, a backslash form \evil.example that some clients normalise to //, an absolute URL with a userinfo part (https://app.example.com@evil.example), a same-origin-looking host that is actually a subdomain of an attacker domain, or a value that the framework rewrites (for example a Rails redirect_to that expands a model attribute, or a 307 that replays the body to another origin). Any of those means the string after resolution is off-origin and the finding is real.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/601.html)

**A next=/returnUrl= parameter whose reflected value only occupies the path, query or fragment of a Location value whose scheme and authority are fixed in code is not an open redirect, because the browser resolves the authority from the code and only a same-origin path segment is attacker-controlled.**

Mechanism: the setter builds the redirect as a fixed prefix plus attacker text, for example header("Location: https://app.example.com/go?next=" . $_GET['next']) or Response.Redirect("/account/return?to=" + to). The only field the attacker controls is the tail of the path/query, so the browser navigates to app.example.com and the off-domain string is never dereferenced; it is inert data shown to that same site. The check that separates true from false is whether the attacker can influence the BEGINNING of the URL (scheme and authority), not whether the string 'https://evil.example' appears anywhere in the response. Triage test: replace the value with //evil.example/x and with @evil.example and see whether the request leaves the origin; if the browser stays on app.example.com in both cases, the finding is a reflected-parameter or link-content issue, not an open redirect. Recorded in CWE-601 detection guidance, which names input influence over the beginning of a URL as the thing that matters for reducing false positives, and the OWASP cheat sheet's rule that only values validated against a list of trusted URLs/hosts may be used as a redirect destination.

- *Disproof:* The rule stops being true the moment the attacker can reach the scheme or authority: a Location value that is the bare parameter (Location: <user>), a value concatenated without a separator after the host so that user input supplies userinfo or a new authority (https://app.example.com@evil.example, //evil.example, \evil.example, or a value beginning with a scheme), a prefix assembled by string concatenation from a configurable base, or a second redirect hop where the stored off-domain string is itself used as the next Location. Any of those makes the same reflected string the actual navigation target and the finding real.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/601.html)

**A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.**

Parse the Location value with the same algorithm the browser uses and compare authority against the request Host, port and scheme included. ZAP's own remediation for this class is exactly this check: safe redirect functionality redirects only to relative URIs or to a list of trusted domains, which means a relative-path Location is the fixed behaviour, not the bug. The genuine variant, documented in Zscaler's research, is an endpoint that will redirect to any domain the caller supplies - a warning or interstitial page used as a redirector - and there the authority genuinely leaves the origin. Same signal (user input in the Location header), opposite verdict; the only discriminator is the resolved authority.

- *Disproof:* The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
- *Evidence:* high_confidence — [zaproxy.org](https://www.zaproxy.org/docs/alerts/10028/); [zscaler.com](https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam)

**A redirect parameter whose value must resolve to a path on the application's own origin is not an open redirect; the finding requires the attacker to control the destination origin, not merely the path or the query string that follows the application's own host.**

Mechanism: A redirect parameter whose value must resolve to a path on the application's own origin is not an open redirect; the finding requires the attacker to control the destination origin, not merely the path or the query string that follows the application's own host. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the value is resolved by a client rather than the server — a protocol-relative value, a scheme-relative or backslash-normalised form, or a value that a downstream client (email client, chat renderer, mobile deep-link handler) reinterprets as absolute — because the server-side check passes while the user agent still leaves the origin.

- *Disproof:* The rule is wrong when the value is resolved by a client rather than the server — a protocol-relative value, a scheme-relative or backslash-normalised form, or a value that a downstream client (email client, chat renderer, mobile deep-link handler) reinterprets as absolute — because the server-side check passes while the user agent still leaves the origin.
- *Evidence:* high_confidence — [expressjs.com](https://expressjs.com/en/advanced/best-practice-security.html); [openid.net](https://openid.net/specs/openid-connect-core-1_0.html)

**An authorization server answering with a `redirect_uri_mismatch` error has refused the unregistered destination, so that exchange is the authorisation server's defence working and must not be reported as an open redirect on the client.**

Mechanism: An authorization server answering with a `redirect_uri_mismatch` error has refused the unregistered destination, so that exchange is the authorisation server's defence working and must not be reported as an open redirect on the client. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the client is the component at fault — it holds a pre-registered wildcard or prefix pattern that the server honours, so an attacker's host matches a registered pattern and the code is returned to it — or when the mismatch is only for the tested variant while a weaker registered form still accepts the malicious origin, in which case the server's exact-match rule is not what stopped the attack.

- *Disproof:* The rule is wrong when the client is the component at fault — it holds a pre-registered wildcard or prefix pattern that the server honours, so an attacker's host matches a registered pattern and the code is returned to it — or when the mismatch is only for the tested variant while a weaker registered form still accepts the malicious origin, in which case the server's exact-match rule is not what stopped the attack.
- *Evidence:* high_confidence — [developers.google.com](https://developers.google.com/identity/protocols/oauth2/web-server); [openid.net](https://openid.net/specs/openid-connect-core-1_0.html)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An open-redirect defence that inspects the destination with a real URL parser and compares the host is bypassed by any implementation that does a substring, suffix or endsWith test on the raw string, because a value such as an attacker host whose name merely contains the allowed host, or an allowed host with a trailing credential-holding prefix, satisfies the substring test while resolving elsewhere.**

Mechanism: An open-redirect defence that inspects the destination with a real URL parser and compares the host is bypassed by any implementation that does a substring, suffix or endsWith test on the raw string, because a value such as an attacker host whose name merely contains the allowed host, or an allowed host with a trailing credential-holding prefix, satisfies the substring test while resolving elsewhere. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the check parses with a WHATWG-compatible URL constructor and compares the parsed host for exact equality, because the confusable forms then fail to match and no substring confusion is possible; a check that also rejects relative and scheme-relative input closes the remaining variants.

- *Disproof:* The rule is false when the check parses with a WHATWG-compatible URL constructor and compares the parsed host for exact equality, because the confusable forms then fail to match and no substring confusion is possible; a check that also rejects relative and scheme-relative input closes the remaining variants.
- *Evidence:* high_confidence — [expressjs.com](https://expressjs.com/en/advanced/best-practice-security.html); [openid.net](https://openid.net/specs/openid-connect-core-1_0.html)

## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.**

Step: request the authorize endpoint with a redirect_uri pointing at an attacker origin and compare the response with the same request carrying an unregistered host; when the response is a 3xx whose Location field carries the attacker origin, the open_redirect primitive is confirmed. That open_redirect then chains into oauth: the victim authenticates at the real authorization server, which returns the authorization code to the attacker's redirect_uri, and the attacker exchanges that code for tokens if PKCE or client authentication does not stop the exchange. Note that a redirect which resolves to the attacker origin after a user-agent follow is enough; the user agent may redirect to the URI referenced by the Location field value even when the specific status code is not understood.

- *Disproof:* If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability); [httpwg.org](https://httpwg.org/specs/rfc7231.html)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
