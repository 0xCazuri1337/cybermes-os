# Open Redirect

> surface: `web` · CWE: 601 · OWASP: A01:2021
> maturity: **researching** — 5 items, 5 supported, 2 FP rules, 0 chains

A redirect target is not constrained to a trusted destination.

**Aliases:** open redirect, unvalidated redirect, redirect uri validation

## Signal

- **An open redirect is only present when user-supplied input reaches the destination of a redirect without validation, as distinct from any redirect that exists.**  
  `high_confidence` · score 0.929 · disproved by: If no supplied parameter alters the Location host, or the destination is always a fixed internal route, there is no open redirect to pursue.
  sources: <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory> · <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/>

## Validation

- **An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.**  
  `high_confidence` · score 0.874 · disproved by: If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.
  sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications> · <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/>

## Fp Rule

- **A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.**  
  `high_confidence` · score 0.948 · disproved by: The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.**  
  `high_confidence` · score 0.918 · disproved by: The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
  sources: <https://www.zaproxy.org/docs/alerts/10028/> · <https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam>

## Chain Link

- **An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.**  
  `high_confidence` · score 0.984 · disproved by: If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability>

## Known gaps

Not yet satisfied: `items`, `chain`
