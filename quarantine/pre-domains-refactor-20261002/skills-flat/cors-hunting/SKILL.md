---
name: cors-hunting
description: Use when hunting CORS Misconfiguration in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# CORS Misconfiguration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 942 · OWASP A05:2021
> evidence: 6 items, 6 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

The cross-origin policy grants a foreign origin more access than intended.

**Also called:** cors, cross origin resource sharing, cors misconfiguration


## Prerequisites (do not start without these)

- A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.
  - **Disproof:** If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
  - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Recon signals (where to look)

- An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.
  - **Disproof:** If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
  - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Techniques (what to change)

- An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.
  - **Disproof:** The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.
  - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
  - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>

## False-positive rules (when to reject it)

- Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.
  - **Disproof:** The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.
  - Sources: <https://www.zaproxy.org/docs/alerts/40040-3/> · <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
- An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.
  - **Disproof:** A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
  - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>

---
Full class document: `skills/Web/cors/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
