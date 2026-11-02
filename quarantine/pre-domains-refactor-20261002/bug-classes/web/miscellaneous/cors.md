# CORS Misconfiguration

## Definition

The cross-origin policy grants a foreign origin more access than intended.

- **CWE:** 942
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["cors", "cross origin resource sharing", "cors misconfiguration"]

Canonical home for `cors`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.**

Per the Fetch standard a preflight only happens when the method is not CORS-safelisted or an unsafe header is present. Hunt by sending GET or POST carrying only a safelisted Content-Type and no custom header; if the server answers without an OPTIONS round trip the simple-request path is live. Confirm on a state-bearing endpoint that a fetch from a foreign origin with credentials actually reads the body.

*Disproof:* If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.**

Send the endpoint three times with Origin: https://a.invalid, https://b.invalid and no Origin at all, then diff the ACAO returned each time. Reflection is the signal: a fixed allowlist answers only the trusted value or nothing, a reflection answers the decoy verbatim. Add a near-miss origin, the trusted value with one character appended, to separate prefix matching from true reflection.

*Disproof:* If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.

## Exploitation

**An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain; it generally allows a domain to issue requests to other domains, but not to access the responses. A null-origin allowlist entry widens that gate for a specific, attacker-reachable document class. Cross-origin resource calls from internal documents and sandboxed requests can specify the null origin, so a sandboxed iframe on an attacker page, or any user-uploaded HTML rendered in a sandbox, produces exactly the Origin: null the server has been told to trust. Procedure: send the request with an explicit Origin: null header and confirm the reflected ACAO; then prove reachability by loading the same resource from a sandboxed iframe with credentials and reading the body cross-origin. The credentialed half still matters: the response must also signal that it can be shared when the request's credentials mode is include, otherwise the browser will not attach the cookie and the read returns nothing the attacker lacks.

*Disproof:* The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.

**Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.**

Host a page on a domain you control that issues fetch(target, {credentials:'include'}) and exfiltrates the decoded body to your own collector. Run it against the test account's own session, never a real user's. A readable account-scoped body is the finding; a visible ACAO header with no readable body is a configuration observation only.

*Disproof:* If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.**

Probe: send the request twice, once with no Cookie and no Authorization, once with a valid session cookie, and diff the two response bodies. If the bodies are identical (or the unauthenticated one is a 401), there is nothing for a credentialed read to steal. Read the response header block for Access-Control-Allow-Credentials specifically, not for the presence of CORS headers in general. ZAP states the precondition for authenticated cross-origin reads directly: authenticated AJAX queries require Access-Control-Allow-Credentials: true alongside an ACAO that is null or the malicious page's domain. So the rejection test is: wildcard ACAO, no ACAC, and no per-user variation in the body. Sonar's origin-reflection writeup names the mirror-image real bug for contrast: a server that reflects whatever Origin it receives nullifies CSRF protection and permits authenticated requests from any domain - that is echoing, not wildcard, and this rule must not swallow it. Hunting value: this filters the single largest CORS false-positive class, killing every ACAO wildcard hit on public docs, marketing pages, JS bundles, static assets and anonymous catalogue endpoints, none of which a credentialed request can escalate.

*Disproof:* The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.

**An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.**

Before reporting, fetch the same path unauthenticated from a clean session. If the body is byte-identical to the authenticated response, the data was already public and CORS changed nothing about who could read it. Record the unauthenticated diff as the disproof artefact so the triage decision is auditable rather than assumed.

*Disproof:* A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/is-cors-obsolete>
- **portswigger.net** (docs)
  - <https://portswigger.net/web-security/cors/>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/security-implications-cors-node-js/>
- **sonarsource.com** (writeup)
  - <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
- **w3.org** (docs)
  - <https://www.w3.org/TR/cors/>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/40040-3/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
