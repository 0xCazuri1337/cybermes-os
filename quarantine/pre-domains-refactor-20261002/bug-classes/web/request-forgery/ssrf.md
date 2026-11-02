# Server-Side Request Forgery

## Definition

The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.

- **CWE:** CWE-918
- **OWASP:** A10:2021
- **Surface:** web
- **Aliases:** ["ssrf", "server side request forgery", "blind ssrf", "cloud metadata ssrf"]

Canonical home for `ssrf`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.**

Determine the app server's egress posture before rating impact. Infrastructure often permits outbound DNS while filtering outbound HTTP, so a blind SSRF may be real but reach only a resolver. If a network-layer restriction exists the finding is a defense-in-depth gap rather than a confirmed fetch. Record which of DNS resolution, TCP connect, and HTTP response actually occurred; these are three distinct proofs with three different severities.

*Disproof:* If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.**

Generate a unique per-payload domain on a collaborator service, embed it in each candidate URL field (including nested JSON/XML values and secondary fetches), then monitor for DNS and HTTP interactions correlated to that exact token. Correlating a unique token per request avoids false positives from scanners and crawlers. Only an inbound HTTP request counts as proof; a DNS lookup alone is a weaker, separately-graded signal.

*Disproof:* If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.

## Exploitation

**Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.**

From the server, request the link-local metadata address and the cloud vendor DNS name for the metadata service, including IPv6 forms for IPv6-capable instances. Metadata keys commonly expose instance identity, network config, and user-supplied data or credentials written there. Report metadata reachability as a finding with the exact endpoint that answered and the key names visible; do not retrieve or exfiltrate secret values.

*Disproof:* If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.

**SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.**

Probe loopback aliases and private ranges from the app server: 127.0.0.1, localhost, alternative IP encodings of 127.0.0.1, RFC1918 targets, and alternate ports where an admin interface listens. High-value targets are components that treat a request originating locally as trusted, including management interfaces, DR-only unauthenticated admin paths, and sidecar APIs. Response differences (status, body length, timing) reveal reachability even when the body is filtered.

*Disproof:* If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.

**Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.**

Probe parser differentials: userinfo tricks such as https://expected-host:pass@evil-host, fragments such as https://evil-host#expected-host, suffix matching such as https://expected-host.evil-host, percent- and double-encoding, and case variation. Also test rare IP literal forms (dword, octal, hex, short forms) and IPv6 bracket literals. The host production is genuinely ambiguous, so implementations legitimately disagree; judge each payload on which component parsed it.

*Disproof:* If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ssrf-to-cloud-metadata-credential-theft` — ssrf-to-cloud-metadata-credential-theft (goal: `cloud_credential_theft`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.**

Do not upgrade a blind SSRF on the strength of a collaborator hit alone. Without a readable response you cannot show what was retrieved, so keep the finding scoped to 'server makes attacker-directed requests' and state the unproven parts explicitly. Escalate only with additional evidence: a reflected internal response, a distinguishable internal state change, or a second-stage result observed out of band. Otherwise the finding is real but its impact ceiling is unknown.

*Disproof:* If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.

**A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.**

When a blacklist-style filter rejects 127.0.0.1, localhost, or a sensitive path, treat the rejection as a correct control unless you observe the server still connecting. A 4xx, a validation error, or a silent drop with no collaborator traffic is the expected outcome of working filtering. Report bypasses only when a connection to the blocked resource is demonstrated, and pair every candidate bypass with a baseline request that the filter legitimately refuses.

*Disproof:* If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.

**A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.**

Two distinct controls are involved: a validator that inspects the supplied URL, and the HTTP client that follows redirects and resolves DNS. A validator rejecting internal addresses and then being defeated by a redirect is a redirect-following defect; a fetcher whose hostname resolves to an internal address after validation is a DNS-resolution defect. Each has a different remediation, so conflating them lets a client patch the validator and leave the bypass intact.

*Disproof:* If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.

**Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.**

A blind SSRF test produces silence in three different situations: the payload was malformed, the fetch never happened, or the fetch happened and egress blocked the response or the DNS resolution. Before concluding a negative result, confirm the same host receives a callback from a request the application is known to make. Without that control, reporting 'no callback' as a clean result is a false negative dressed as evidence.

*Disproof:* If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
**Hypothesis:** A file:// scheme in the URL parameter reads local files, proving SSRF
- Invalidated by: The endpoint's purpose is avatar upload and file storage, so a file scheme is a local file inclusion issue against a different trust boundary, not a request forgery
- **Rejection rule:** A file:// read is LFI, not SSRF; classify the primitive before reporting, because the two have different root causes, owners and fixes

**Hypothesis:** A hostname allowlist is bypassed because a public hostname resolving to an internal address was fetched
- Invalidated by: The hostname resolved publicly from the attacker's network but to a private address from inside the organisation's split-horizon DNS, so the internal content came from the target's own resolver, not from a bypass
- **Rejection rule:** Internal content behind a public hostname may be split-horizon DNS rather than a filter bypass; resolve the name from both networks before attributing it to validation logic

**Hypothesis:** The URL is fetched by the server because the resulting image renders in the page
- Invalidated by: The URL was returned as a plain img src attribute in the HTML and the browser performed the retrieval, so nothing server-side was involved
- **Rejection rule:** A URL in an img src is a client-side fetch by definition; SSRF requires evidence the SERVER retrieved it, not that a browser did

**Hypothesis:** The URL is validated against an allowlist but internal hosts are reachable through DNS rebinding
- Invalidated by: The response came from the ATTACKER's own loopback service, which is reachable from the attacker's machine anyway, so nothing internal to the target was disclosed
- **Rejection rule:** A rebind that resolves to the attacker's own loopback proves nothing; the rebound address must be inside the victim network for impact to exist

**Hypothesis:** The endpoint is blind SSRF because a slow internal host produces a measurable delay
- Invalidated by: The delay was present on the public-URL baselines too and matched the delay of a deliberately slow public host, so timing reflects the outbound network, not a reachable internal service
- **Rejection rule:** A blind SSRF claim from timing needs the delay to track the payload across many samples; a uniformly slow network produces the same symptom with no vulnerability

**Hypothesis:** The image-fetch endpoint is vulnerable to SSRF because it returns HTTP 200 for an internal URL
- Invalidated by: An unresolvable domain and a malformed URL also returned HTTP 200 with the same non-empty placeholder body, so the 200 is the endpoint accepting the parameter, not a successful outbound fetch
- **Rejection rule:** A fetch endpoint that returns 200 for unresolvable and malformed URLs is not proving SSRF; the body must contain content that could only come from the target you supplied

**Hypothesis:** The server follows redirects, so an allowed host redirecting to a blocked internal address proves SSRF
- Invalidated by: The internal content was returned in the CLIENT's response to the attacker, not in the server's fetch result, so the server returned the redirect and stopped - it did not follow it
- **Rejection rule:** Redirect-based SSRF requires the internal content in the SERVER's fetch result; a 302 handed back to your own client is the server refusing to follow, not a bypass

**Hypothesis:** The webhook endpoint is exploitable because it delivers a POST to an attacker-controlled URL
- Invalidated by: The webhook destination must be configured by an authenticated administrator, the delivered payload contained only non-sensitive event metadata, and no internal network was reachable through it
- **Rejection rule:** A webhook is not SSRF when only an authenticated owner can set the destination and the delivered data is non-sensitive; the capability is the feature

**Hypothesis:** A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.
- Invalidated by: If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
- **Rejection rule:** A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.

**Hypothesis:** A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.
- Invalidated by: If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
- **Rejection rule:** A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.

**Hypothesis:** A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.
- Invalidated by: If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
- **Rejection rule:** A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.

**Hypothesis:** Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.
- Invalidated by: If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
- **Rejection rule:** Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.

## Validation

**A DNS lookup with no follow-up HTTP request indicates the request was blocked by network filtering, not that the SSRF is a false positive.**

When you see resolution of your unique domain but zero inbound HTTP, confirm the egress path rather than dismissing the finding. Re-test with an alternate destination and compare: if other external hosts also fail, the app is egress-restricted and the bug is present but unexploitable from that network. Record it as 'confirmed request initiation, filtered egress' so remediation targets both the SSRF and the network policy.

*Disproof:* If inbound HTTP requests to the same unique domain do arrive under identical egress conditions, the failure was transient and the DNS-only pattern is not explained by filtering.

**A bypass is only proven when the component that actually performs the fetch resolved a different host than the validating component approved.**

For each candidate bypass, reconstruct the fetch: which library or client made the request, which normalization step it applied, and which host it connected to. Compare that against what the filter inspected. A payload rejected by a strict allowlist comparison is not a bypass even if a client would have parsed it differently. Prefer evidence from the fetcher's own resolution (observed connection, response, timing) over reasoning about the regex.

*Disproof:* If the fetch connects to the allowlisted host for every variant, the allowlist held and no bypass occurred.

## Impact

**SSRF is also an attribution and abuse-laundering primitive: requests appear to originate from the victim organization.**

Frame impact around what the server can reach on the attacker's behalf: spoofed source IP toward third parties, internal-only protocols and ports, and possible command execution in some configurations. Any request your server makes toward a host you do not own is a third-party interaction you cannot clean up, so prove impact against hosts you control or the target's own internal range, and stop before spraying third-party infrastructure.

*Disproof:* If the server is strictly limited to a small allowlisted set of first-party hosts with redirects disabled, onward third-party abuse and attribution laundering are not reachable.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/918.html>
- **datatracker.ietf.org** (standard)
  - <https://datatracker.ietf.org/doc/html/rfc9110>
- **ietf.org** (standards_body)
  - <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html>
  - <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html>
- **owasp.org** (vendor_advisory)
  - <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>
- **portswigger.net** (research_doc)
  - <https://portswigger.net/web-security/ssrf>
  - <https://portswigger.net/web-security/ssrf/blind>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc3986.html>
- **unit42.paloaltonetworks.com** (advisory)
  - <https://unit42.paloaltonetworks.com/threat-brief-owassrf/>
- **wiz.io** (research)
  - <https://www.wiz.io/blog/red-agent-pov-ssrf>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
