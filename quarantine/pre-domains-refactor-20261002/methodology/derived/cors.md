# Methodology — CORS Misconfiguration

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class cors --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The cross-origin policy grants a foreign origin more access than intended.

**References.** CWE-942 · A05:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.**

Per the Fetch standard a preflight only happens when the method is not CORS-safelisted or an unsafe header is present. Hunt by sending GET or POST carrying only a safelisted Content-Type and no custom header; if the server answers without an OPTIONS round trip the simple-request path is live. Confirm on a state-bearing endpoint that a fetch from a foreign origin with credentials actually reads the body.

- *Disproof:* If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/); [w3.org](https://www.w3.org/TR/cors/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.**

Send the endpoint three times with Origin: https://a.invalid, https://b.invalid and no Origin at all, then diff the ACAO returned each time. Reflection is the signal: a fixed allowlist answers only the trusted value or nothing, a reflection answers the decoy verbatim. Add a near-miss origin, the trusted value with one character appended, to separate prefix matching from true reflection.

- *Disproof:* If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/); [w3.org](https://www.w3.org/TR/cors/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.**

Host a page on a domain you control that issues fetch(target, {credentials:'include'}) and exfiltrates the decoded body to your own collector. Run it against the test account's own session, never a real user's. A readable account-scoped body is the finding; a visible ACAO header with no readable body is a configuration observation only.

- *Disproof:* If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/is-cors-obsolete); [w3.org](https://www.w3.org/TR/cors/)

**An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain; it generally allows a domain to issue requests to other domains, but not to access the responses. A null-origin allowlist entry widens that gate for a specific, attacker-reachable document class. Cross-origin resource calls from internal documents and sandboxed requests can specify the null origin, so a sandboxed iframe on an attacker page, or any user-uploaded HTML rendered in a sandbox, produces exactly the Origin: null the server has been told to trust. Procedure: send the request with an explicit Origin: null header and confirm the reflected ACAO; then prove reachability by loading the same resource from a sandboxed iframe with credentials and reading the body cross-origin. The credentialed half still matters: the response must also signal that it can be shared when the request's credentials mode is include, otherwise the browser will not attach the cookie and the read returns nothing the attacker lacks.

- *Disproof:* The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [w3.org](https://www.w3.org/TR/cors/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.**

Probe: send the request twice, once with no Cookie and no Authorization, once with a valid session cookie, and diff the two response bodies. If the bodies are identical (or the unauthenticated one is a 401), there is nothing for a credentialed read to steal. Read the response header block for Access-Control-Allow-Credentials specifically, not for the presence of CORS headers in general. ZAP states the precondition for authenticated cross-origin reads directly: authenticated AJAX queries require Access-Control-Allow-Credentials: true alongside an ACAO that is null or the malicious page's domain. So the rejection test is: wildcard ACAO, no ACAC, and no per-user variation in the body. Sonar's origin-reflection writeup names the mirror-image real bug for contrast: a server that reflects whatever Origin it receives nullifies CSRF protection and permits authenticated requests from any domain - that is echoing, not wildcard, and this rule must not swallow it. Hunting value: this filters the single largest CORS false-positive class, killing every ACAO wildcard hit on public docs, marketing pages, JS bundles, static assets and anonymous catalogue endpoints, none of which a credentialed request can escalate.

- *Disproof:* The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.
- *Evidence:* high_confidence — [sonarsource.com](https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/); [zaproxy.org](https://www.zaproxy.org/docs/alerts/40040-3/)

**An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.**

Before reporting, fetch the same path unauthenticated from a clean session. If the body is byte-identical to the authenticated response, the data was already public and CORS changed nothing about who could read it. Record the unauthenticated diff as the disproof artefact so the triage decision is auditable rather than assumed.

- *Disproof:* A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/is-cors-obsolete); [w3.org](https://www.w3.org/TR/cors/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
