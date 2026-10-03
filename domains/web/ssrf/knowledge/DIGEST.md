# Server-Side Request Forgery

> surface: `web` · CWE: CWE-918 · OWASP: A10:2021
> maturity: **mature** — 17 items, 17 supported, 16 FP rules, 1 chains

The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.

**Aliases:** ssrf, server side request forgery, blind ssrf, cloud metadata ssrf

## Prerequisite

- **Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.**  
  `high_confidence` · score 0.8115 · disproved by: If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>

## Signal

- **A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.**  
  `high_confidence` · score 0.853 · disproved by: If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>

## Technique

- **Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.**  
  `high_confidence` · score 0.885 · disproved by: If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.**  
  `high_confidence` · score 0.8805 · disproved by: If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
  sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://portswigger.net/web-security/ssrf>
- **Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.**  
  `high_confidence` · score 0.8805 · disproved by: If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
  sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://portswigger.net/web-security/ssrf>
- **The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.**  
  `high_confidence` · score 0.872 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
- **SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header**  
  `high_confidence` · score 0.817 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
- **Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ).**  
  `high_confidence` · score 0.7895 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>

## Validation

- **A bypass is only proven when the component that actually performs the fetch resolved a different host than the validating component approved.**  
  `high_confidence` · score 0.924 · disproved by: If the fetch connects to the allowlisted host for every variant, the allowlist held and no bypass occurred.
  sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **A DNS lookup with no follow-up HTTP request indicates the request was blocked by network filtering, not that the SSRF is a false positive.**  
  `high_confidence` · score 0.839 · disproved by: If inbound HTTP requests to the same unique domain do arrive under identical egress conditions, the failure was transient and the DNS-only pattern is not explained by filtering.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>

## Fp Rule

- **Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.**  
  `high_confidence` · score 0.8965 · disproved by: If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html> · <https://portswigger.net/web-security/ssrf>
- **A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.**  
  `high_confidence` · score 0.8665 · disproved by: If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf>
- **A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.**  
  `high_confidence` · score 0.853 · disproved by: If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
- **A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.**  
  `high_confidence` · score 0.814 · disproved by: If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/ssrf>

## Impact

- **SSRF is also an attribution and abuse-laundering primitive: requests appear to originate from the victim organization.**  
  `high_confidence` · score 0.8255 · disproved by: If the server is strictly limited to a small allowlisted set of first-party hosts with redirects disabled, onward third-party abuse and attribution laundering are not reachable.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>

## Chain Link

- **An SSRF that the application's own filters do not recognise as reaching a metadata endpoint still yields instance credentials, which are then spent with the ambient authority of the hosting application identity rather than the anonymous attacker.**  
  `high_confidence` · score 0.984 · disproved by: Refuted when the metadata service requires an identity-bound header such as an instance identity document or when the workload runs with no attached service account; the fetch then returns nothing an attacker can redeem.
  sources: <https://unit42.paloaltonetworks.com/threat-brief-owassrf/> · <https://www.wiz.io/blog/red-agent-pov-ssrf>
- **An SSRF whose scheme is attacker-chained into file://, gopher://, or dict:// upgrades a read-only web fetch into local file access or arbitrary-protocol byte delivery.**  
  `high_confidence` · score 0.869 · disproved by: If the fetcher rejects every non-HTTP scheme with an error and never dereferences them, the scheme-abuse chain is unavailable.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>

## False-positive rules

- **Hypothesis:** The image-fetch endpoint is vulnerable to SSRF because it returns HTTP 200 for an internal URL
  - **Invalidated by:** An unresolvable domain and a malformed URL also returned HTTP 200 with the same non-empty placeholder body, so the 200 is the endpoint accepting the parameter, not a successful outbound fetch
  - **Rule:** A fetch endpoint that returns 200 for unresolvable and malformed URLs is not proving SSRF; the body must contain content that could only come from the target you supplied

- **Hypothesis:** A hostname allowlist is bypassed because a public hostname resolving to an internal address was fetched
  - **Invalidated by:** The hostname resolved publicly from the attacker's network but to a private address from inside the organisation's split-horizon DNS, so the internal content came from the target's own resolver, not from a bypass
  - **Rule:** Internal content behind a public hostname may be split-horizon DNS rather than a filter bypass; resolve the name from both networks before attributing it to validation logic

- **Hypothesis:** The server follows redirects, so an allowed host redirecting to a blocked internal address proves SSRF
  - **Invalidated by:** The internal content was returned in the CLIENT's response to the attacker, not in the server's fetch result, so the server returned the redirect and stopped - it did not follow it
  - **Rule:** Redirect-based SSRF requires the internal content in the SERVER's fetch result; a 302 handed back to your own client is the server refusing to follow, not a bypass

- **Hypothesis:** The endpoint is blind SSRF because a slow internal host produces a measurable delay
  - **Invalidated by:** The delay was present on the public-URL baselines too and matched the delay of a deliberately slow public host, so timing reflects the outbound network, not a reachable internal service
  - **Rule:** A blind SSRF claim from timing needs the delay to track the payload across many samples; a uniformly slow network produces the same symptom with no vulnerability

- **Hypothesis:** A file:// scheme in the URL parameter reads local files, proving SSRF
  - **Invalidated by:** The endpoint's purpose is avatar upload and file storage, so a file scheme is a local file inclusion issue against a different trust boundary, not a request forgery
  - **Rule:** A file:// read is LFI, not SSRF; classify the primitive before reporting, because the two have different root causes, owners and fixes

- **Hypothesis:** The URL is fetched by the server because the resulting image renders in the page
  - **Invalidated by:** The URL was returned as a plain img src attribute in the HTML and the browser performed the retrieval, so nothing server-side was involved
  - **Rule:** A URL in an img src is a client-side fetch by definition; SSRF requires evidence the SERVER retrieved it, not that a browser did

- **Hypothesis:** The webhook endpoint is exploitable because it delivers a POST to an attacker-controlled URL
  - **Invalidated by:** The webhook destination must be configured by an authenticated administrator, the delivered payload contained only non-sensitive event metadata, and no internal network was reachable through it
  - **Rule:** A webhook is not SSRF when only an authenticated owner can set the destination and the delivered data is non-sensitive; the capability is the feature

- **Hypothesis:** The URL is validated against an allowlist but internal hosts are reachable through DNS rebinding
  - **Invalidated by:** The response came from the ATTACKER's own loopback service, which is reachable from the attacker's machine anyway, so nothing internal to the target was disclosed
  - **Rule:** A rebind that resolves to the attacker's own loopback proves nothing; the rebound address must be inside the victim network for impact to exist

- **Hypothesis:** A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.
  - **Invalidated by:** If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
  - **Rule:** A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.

- **Hypothesis:** A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.
  - **Invalidated by:** If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
  - **Rule:** A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.

- **Hypothesis:** A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.
  - **Invalidated by:** If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
  - **Rule:** A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.

- **Hypothesis:** Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.
  - **Invalidated by:** If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
  - **Rule:** Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.

## Related classes (via chains)

- `api_trust` API-to-API Trust Failures (3 chains)
