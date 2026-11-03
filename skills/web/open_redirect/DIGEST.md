<!-- GENERATED from db/wks.db — do not edit -->
# Open Redirect

> surface: `web` · CWE: 601 · OWASP: A01:2021
> maturity: **mature** — 29 items, 22 supported, 6 FP rules, 1 chains

A redirect target is not constrained to a trusted destination.

**Aliases:** open redirect, unvalidated redirect, redirect uri validation

## Technique

- **When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.**  
  `high_confidence` · score 0.8815 · disproved by: The redirect parameter refuses external hosts or ignores off-site values and always resolves to a fixed internal path.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/> · <https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md>
- **A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated,”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an ”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>

## Validation

- **An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.**  
  `high_confidence` · score 0.899 · disproved by: If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.
  sources: <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/> · <https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications>
- **An open redirect is proved by a 3xx response whose Location header resolves to an attacker-controlled origin, captured with the redirect not followed; the presence of a `next`, `returnUrl` or `redirect` parameter on a request that returned 200 proves nothing.**  
  `high_confidence` · score 0.893 · disproved by: The claim is false when the response cannot be observed with its headers intact — a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured to follow redirects — in which case the Location must be captured from a raw exchange or from the browser's network log, and a screenshot of the final page is insufficient evidence.
  sources: <https://developers.google.com/identity/protocols/oauth2/web-server> · <https://expressjs.com/en/advanced/best-practice-security.html>

## Fp Rule

- **A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.**  
  `high_confidence` · score 0.948 · disproved by: The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A 3xx response whose Location value is a relative reference (/login, ~/folder/Login.aspx, ../dashboard) or an absolute URL on the request's own origin is not an open redirect, because URL resolution against the current base keeps the navigation on the same origin, so no untrusted site ever receives the victim.**  
  `high_confidence` · score 0.924 · disproved by: The rule fails if the resolved value's authority differs from the request origin in any way the browser honours: a protocol-relative //evil.example, a backslash form \evil.example that some clients normalise to //, an absolute URL with a userinfo part (https://app.example.com@evil.example), a same-origin-looking host that is actually a subdomain of an attacker domain, or a value that the framework rewrites (for example a Rails redirect_to that expands a model attribute, or a 307 that replays the body to another origin). Any of those means the string after resolution is off-origin and the finding is real.
  sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- **A next=/returnUrl= parameter whose reflected value only occupies the path, query or fragment of a Location value whose scheme and authority are fixed in code is not an open redirect, because the browser resolves the authority from the code and only a same-origin path segment is attacker-controlled.**  
  `high_confidence` · score 0.924 · disproved by: The rule stops being true the moment the attacker can reach the scheme or authority: a Location value that is the bare parameter (Location: <user>), a value concatenated without a separator after the host so that user input supplies userinfo or a new authority (https://app.example.com@evil.example, //evil.example, \evil.example, or a value beginning with a scheme), a prefix assembled by string concatenation from a configurable base, or a second redirect hop where the stored off-domain string is itself used as the next Location. Any of those makes the same reflected string the actual navigation target and the finding real.
  sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- **A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.**  
  `high_confidence` · score 0.918 · disproved by: The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
  sources: <https://www.zaproxy.org/docs/alerts/10028/> · <https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam>
- **An authorization server answering with a `redirect_uri_mismatch` error has refused the unregistered destination, so that exchange is the authorisation server's defence working and must not be reported as an open redirect on the client.**  
  `high_confidence` · score 0.838 · disproved by: The rule is wrong when the client is the component at fault — it holds a pre-registered wildcard or prefix pattern that the server honours, so an attacker's host matches a registered pattern and the code is returned to it — or when the mismatch is only for the tested variant while a weaker registered form still accepts the malicious origin, in which case the server's exact-match rule is not what stopped the attack.
  sources: <https://developers.google.com/identity/protocols/oauth2/web-server> · <https://openid.net/specs/openid-connect-core-1_0.html>

## Evidence

- **A convincing observation for this class is: If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary.**  
  `high_confidence` · score 0.9205 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.1fb211f8) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A convincing observation for this class is: HEAD The HEAD method is identical to GET except that the server MUST NOT send a message body in the response (i.e., the response terminates at the end of the header section).**  
  `high_confidence` · score 0.893 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.77f2d9a5) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A convincing observation for this class is: Redirection to a different resource, identified by the Location field, that can represent an indirect response to the request, as in the 303 (See Other) status code.**  
  `high_confidence` · score 0.893 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.64eea101) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A convincing observation for this class is: Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response.**  
  `high_confidence` · score 0.893 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.74923980) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A convincing observation for this class is: Redirection 3xx The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request.**  
  `high_confidence` · score 0.8655 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.44375ffe) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A convincing observation for this class is: that offers a choice of matching resources, each capable of representing the original request target, as in the 300 (Multiple Choices) status code.**  
  `high_confidence` · score 0.8655 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.3b706ea3) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A convincing observation for this class is: A server that receives an Expect field-value other than 100-continue MAY respond with a 417 (Expectation Failed) status code to indicate that the unexpected expectation cannot be met.**  
  `high_confidence` · score 0.838 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.852c145c) states the full boundary.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>

## Impact

- **The principal business impact of open redirect is phishing and credential theft at scale, because the trusted brand domain carries the malicious payload; secondary impacts include OAuth token theft, SSRF, XSS, and bypass of allowlist-based security controls.**  
  `high_confidence` · score 0.8965 · disproved by: If the organization disables open redirects at the reverse proxy, enforces strict allowlists, or the redirect is limited to a single internal hop that is then validated, the phishing and chaining impact is materially reduced.
  sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://guide.codepure.com/vulnerabilities/cwe-601> · <https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/>

## Bypass

- **An open-redirect defence that inspects the destination with a real URL parser and compares the host is bypassed by any implementation that does a substring, suffix or endsWith test on the raw string, because a value such as an attacker host whose name merely contains the allowed host, or an allowed host with a trailing credential-holding prefix, satisfies the substring test while resolving elsewhere.**  
  `high_confidence` · score 0.8655 · disproved by: The rule is false when the check parses with a WHATWG-compatible URL constructor and compares the parsed host for exact equality, because the confusable forms then fail to match and no substring confusion is possible; a check that also rejects relative and scheme-relative input closes the remaining variants.
  sources: <https://expressjs.com/en/advanced/best-practice-security.html> · <https://openid.net/specs/openid-connect-core-1_0.html>

## Chain Link

- **An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.**  
  `high_confidence` · score 0.984 · disproved by: If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability>

## Overview

- **Applications that accept user-supplied URLs directly into redirect parameters (next, return_to, redirect, dest, continue, goto) without validating the destination against an allowlist are vulnerable to open redirect (CWE-601, OWASP A01:2021 - Broken Access Control).**  
  `high_confidence` · score 0.905 · disproved by: If the application validates the target against an allowlist of trusted domains, if it resolves relative and encoded URLs before validation, or if it only checks the initial URL rather than the final destination, the redirect is not exploitable.
  sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/> · <https://www.sensagraph.com/knowledge-base/open-redirect>

## Vulnerability

- **An open redirect incorporates user-controllable input into a Location/href target without validating it against a trusted allowlist, enabling phishing and OAuth token/code theft.**  
  `high_confidence` · score 0.8965 · disproved by: If redirect destinations are server-mapped identifiers, or if the parsed host is compared by exact matches against an allowlisted set of trusted domains (with scheme, port, backslash, and encoded variants rejected), open redirect is neutralized. A redirect whose final Location is not within the allowlist disproves exploitation.
  sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://portswigger.net/kb/issues/00500100_open-redirection-reflected> · <https://safeguard.sh/resources/blog/preventing-open-redirect-vulnerabilities>

## False-positive rules

- **Hypothesis:** An endpoint reflects a redirect parameter into the Location header, therefore it is an open redirect
  - **Invalidated by:** The 302 pointed back at the same host with the parameter echoed into the URL. No request ever left the origin, so an attacker cannot place their page in the redirect chain
  - **Rule:** A reflected redirect parameter is not an open redirect. Resolve the Location and confirm the 3xx leaves the origin: a same-host 302 with the parameter echoed is not a finding, and 'reflected parameter' alone will be read as padding on review
