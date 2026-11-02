# Methodology — Open Redirect

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class open_redirect --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.**

Send an absolute URL to your own collector as the destination parameter and capture the exact Location header returned. Then test whether validation is a real allowlist or a naive check by trying a near-miss host such as the trusted domain prefixed onto your collector. If the near-miss is accepted, the destination check is bypassable and the finding is confirmed at the bypass level.

- *Disproof:* If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications); [snyk.io](https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.**

The observation is a request to a first-party-looking Microsoft or Google authorize URL that returns a 302 to an attacker domain, which scans as a textbook open redirect on a trusted host. A distinct class of redirection abuse puts the redirection target URL in the OAuth provider's framework: the third-party application registration, where no validation of that URL is applied by the application, and the redirection target URL will be missing from the legitimate URL. The detection that fires is therefore on the identity provider's redirect endpoint, but the controllable value lives in the tenant's consent record for a specific client id, not in any parameter the web application hands to the browser. The benign explanation is that the tenant's administrators or a sanctioned integration registered that client with that redirect_uri. The distinguishing test is attribution: replay the same redirect chain while substituting a client id the tenant never registered, or one registered with a different redirect_uri. If the arbitrary destination only ever appears for a known client id, it is a tenant configuration review item (a malicious or over-permissive app consent), not a web application redirect flaw to be fixed in code.

- *Disproof:* The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
- *Evidence:* high_confidence — [proofpoint.com](https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178)

**A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.**

Parse the Location value with the same algorithm the browser uses and compare authority against the request Host, port and scheme included. ZAP's own remediation for this class is exactly this check: safe redirect functionality redirects only to relative URIs or to a list of trusted domains, which means a relative-path Location is the fixed behaviour, not the bug. The genuine variant, documented in Zscaler's research, is an endpoint that will redirect to any domain the caller supplies - a warning or interstitial page used as a redirector - and there the authority genuinely leaves the origin. Same signal (user input in the Location header), opposite verdict; the only discriminator is the resolved authority.

- *Disproof:* The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
- *Evidence:* high_confidence — [zaproxy.org](https://www.zaproxy.org/docs/alerts/10028/); [zscaler.com](https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.**

Step: request the authorize endpoint with a redirect_uri pointing at an attacker origin and compare the response with the same request carrying an unregistered host; when the response is a 3xx whose Location field carries the attacker origin, the open_redirect primitive is confirmed. That open_redirect then chains into oauth: the victim authenticates at the real authorization server, which returns the authorization code to the attacker's redirect_uri, and the attacker exchanges that code for tokens if PKCE or client authentication does not stop the exchange. Note that a redirect which resolves to the attacker origin after a user-agent follow is enough; the user agent may redirect to the URI referenced by the Location field value even when the specific status code is not understood.

- *Disproof:* If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability); [httpwg.org](https://httpwg.org/specs/rfc7231.html)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Test sequence, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
