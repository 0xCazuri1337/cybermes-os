# Methodology — Server-Side Request Forgery

> Derived from 42 verified items. Regenerate with `python -m wks.methodgen --class ssrf --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.

**References.** CWE-918 · A10:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.**

A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.

HackTricks reference: SSRF Vulnerable Platforms (pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

- *Disproof:* Refuted if a registered callback value is never fetched by the server - it only appears in outbound mail or client-side rendering, or registration is pinned to a fixed allowlisted host.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

**Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.**

Determine the app server's egress posture before rating impact. Infrastructure often permits outbound DNS while filtering outbound HTTP, so a blind SSRF may be real but reach only a resolver. If a network-layer restriction exists the finding is a defense-in-depth gap rather than a confirmed fetch. Record which of DNS resolution, TCP connect, and HTTP response actually occurred; these are three distinct proofs with three different severities.

- *Disproof:* If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.**

Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.

HackTricks reference: SSRF Vulnerable Platforms (pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

- *Disproof:* Refuted if the same error class is returned for an empty or syntactically invalid URL that can never produce an outbound request, meaning the errors track input validation rather than a request leaving the host.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

**A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.**

Generate a unique per-payload domain on a collaborator service, embed it in each candidate URL field (including nested JSON/XML values and secondary fetches), then monitor for DNS and HTTP interactions correlated to that exact token. Correlating a unique token per request avoids false positives from scanners and crawlers. Only an inbound HTTP request counts as proof; a DNS lookup alone is a weaker, separately-graded signal.

- *Disproof:* If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

**An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.**

An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.

HackTricks reference: blind ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md)

- *Disproof:* A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/441.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

**A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.**

A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.

HackTricks reference: blind ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md)

- *Disproof:* A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/441.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.**

From the server, request the link-local metadata address and the cloud vendor DNS name for the metadata service, including IPv6 forms for IPv6-capable instances. Metadata keys commonly expose instance identity, network config, and user-supplied data or credentials written there. Report metadata reachability as a finding with the exact endpoint that answered and the key names visible; do not retrieve or exfiltrate secret values.

- *Disproof:* If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [owasp.org](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

**The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.**

The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

- *Disproof:* If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

**SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.**

Probe loopback aliases and private ranges from the app server: 127.0.0.1, localhost, alternative IP encodings of 127.0.0.1, RFC1918 targets, and alternate ports where an admin interface listens. High-value targets are components that treat a request originating locally as trusted, including management interfaces, DR-only unauthenticated admin paths, and sidecar APIs. Response differences (status, body length, timing) reveal reachability even when the body is filtered.

- *Disproof:* If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery); [portswigger.net](https://portswigger.net/web-security/ssrf)

**Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.**

Probe parser differentials: userinfo tricks such as https://expected-host:pass@evil-host, fragments such as https://evil-host#expected-host, suffix matching such as https://expected-host.evil-host, percent- and double-encoding, and case variation. Also test rare IP literal forms (dword, octal, hex, short forms) and IPv6 bracket literals. The host production is genuinely ambiguous, so implementations legitimately disagree; judge each payload on which component parsed it.

- *Disproof:* If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/ssrf); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc3986.html)

**A server-side request forgery is confirmed when a URL supplied by the client is fetched by the server and its response body is reflected back to the client.**

In practice on HTB this shows up as: ### Server-side Request Forgery \(SSRF\)
Next, I needed to get the admin to link his account to mine in order to escalate my privileges. I went back to the `http://consumer.oouch.htb:5000/contact` page, and sent the admin the link with my authorization token request link, which was already activated through the POST message earlier. All I needed was for the admin to click the link to connect our accounts. This was an example of an attack called [Server-side Request Forgery \(SSRF\)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
![](../../.gitbook/assets/oouch13.png)

Write-up provenance: zweilosec/htb-writeups :: linux-machines/hard/oouch-write-up.md (4663 words, classified network).

- *Disproof:* Refuted when the server performs the fetch but returns no attacker-observable signal (status, timing, or body difference), in which case no request forgery is provable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf); [raw.githubusercontent.com](https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/oouch-write-up.md)

**When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.**

When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.

HackTricks reference: Cloud SSRF (pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md)

- *Disproof:* Refuted if requesting a token from the metadata endpoint without naming an identity succeeds and returns a token for the intended user-assigned identity, or if the platform configuration endpoint lists no identities at all.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/441.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md)

**Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.**

Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.

HackTricks reference: SSRF Vulnerable Platforms (pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

- *Disproof:* Refuted if the final artifact is byte-identical whether the callback URL is tester-controlled or replaced with an unreachable one, or the fetched body is never stored or re-rendered anywhere visible.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

**Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.**

Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.

HackTricks reference: SSRF (Server Side Request Forgery) (pentesting-web/ssrf-server-side-request-forgery/README.md)

- *Disproof:* Refuted if a filename containing encoded newlines adds no headers to the outbound request because the request line is percent-encoded, or if the metadata endpoint answers identically regardless of the injected headers.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc9110); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md)

**A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.**

A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.

HackTricks reference: SSRF (Server Side Request Forgery) (pentesting-web/ssrf-server-side-request-forgery/README.md)

- *Disproof:* Refuted if changing the SNI value does not change the host the server connects to - behaviour is identical for an attacker SNI, a bogus SNI and no SNI at all.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc9110); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md)

**Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.**

Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.

HackTricks reference: AEM - Adobe Experience Cloud (network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md)

- *Disproof:* Refuted when the automated sweep reports no SSRF yet a manual request to the same bypassed URL with an attacker-controlled host does produce an outbound callback, which shows the tool missed a live sink.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc9110); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A bypass is only proven when the component that actually performs the fetch resolved a different host than the validating component approved.**

For each candidate bypass, reconstruct the fetch: which library or client made the request, which normalization step it applied, and which host it connected to. Compare that against what the filter inspected. A payload rejected by a strict allowlist comparison is not a bypass even if a client would have parsed it differently. Prefer evidence from the fetcher's own resolution (observed connection, response, timing) over reasoning about the regex.

- *Disproof:* If the fetch connects to the allowlisted host for every variant, the allowlist held and no bypass occurred.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc3986.html)

**A DNS lookup with no follow-up HTTP request indicates the request was blocked by network filtering, not that the SSRF is a false positive.**

When you see resolution of your unique domain but zero inbound HTTP, confirm the egress path rather than dismissing the finding. Re-test with an alternate destination and compare: if other external hosts also fail, the app is egress-restricted and the bug is present but unexploitable from that network. Record it as 'confirmed request initiation, filtered egress' so remediation targets both the SSRF and the network policy.

- *Disproof:* If inbound HTTP requests to the same unique domain do arrive under identical egress conditions, the failure was transient and the DNS-only pattern is not explained by filtering.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

**A filter that rejects a named set of internal addresses is weaker than an address-space check, because every address belongs to one of three spaces and the classification is defined by what the address means rather than by its literal value.**

The Private Network Access framework defines the classification that a real filter needs: every IP address belongs to an IP address space which can be one of three values - local, containing the local host only, so addresses whose target differs for every device; private, containing addresses that have meaning only within the current network, so addresses whose target differs based on network position; and public, containing all other addresses, whose target is the same for all devices globally. The value of this framing for a hunter is that it turns an unbounded deny-list into a closed test. Loopback, link-local, RFC1918, unique-local, carrier-grade NAT, and the cloud metadata address are instances, not the category - so a blocklist that misses one of them, or that misses a range in a network the target is deployed into, is incomplete in a way a space check is not. Testing should therefore cover at least one address from each space, and the report should state which space the target fell into.

- *Disproof:* The claim does not mean a blocklist cannot be sufficient: in a deployment with a small, known internal surface, a deny-list covering every internal range plus a default-deny egress rule at the network layer is a real control, and the browser-side proposal itself is candid that it merely mitigates attacks against private web services and cannot fully solve them. It also fails as a claim of a specific finding if the untested range is not in the target's address plan - a 10.0.0.0/8 that the environment has no reason to use. The disproof has to come from an address that actually resolves and connects to something, not from a range in a table.
- *Evidence:* high_confidence — [pkg.go.dev](https://pkg.go.dev/net/http); [wicg.github.io](https://wicg.github.io/private-network-access/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.**

A blind SSRF test produces silence in three different situations: the payload was malformed, the fetch never happened, or the fetch happened and egress blocked the response or the DNS resolution. Before concluding a negative result, confirm the same host receives a callback from a request the application is known to make. Without that control, reporting 'no callback' as a clean result is a false negative dressed as evidence.

- *Disproof:* If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc9110); [ietf.org](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

**A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.**

When a blacklist-style filter rejects 127.0.0.1, localhost, or a sensitive path, treat the rejection as a correct control unless you observe the server still connecting. A 4xx, a validation error, or a silent drop with no collaborator traffic is the expected outcome of working filtering. Report bypasses only when a connection to the blocked resource is demonstrated, and pair every candidate bypass with a baseline request that the filter legitimately refuses.

- *Disproof:* If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

**A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.**

Do not upgrade a blind SSRF on the strength of a collaborator hit alone. Without a readable response you cannot show what was retrieved, so keep the finding scoped to 'server makes attacker-directed requests' and state the unproven parts explicitly. Escalate only with additional evidence: a reflected internal response, a distinguishable internal state change, or a second-stage result observed out of band. Otherwise the finding is real but its impact ceiling is unknown.

- *Disproof:* If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

**A payload that a URL parser accepts with the host you intended does not prove the component that performs the fetch will use that host, because parsing and fetching are separate steps and are frequently performed by different code.**

The corpus already carries identify_which_component_parsed as a validation rule; this is its sharpest form. Go's net/url documents that trying to parse a hostname and path without a scheme is invalid but may not necessarily return an error, due to parsing ambiguities - so a payload that produces a parse error is not thereby blocked, and one that produces no error is not thereby going to be fetched as you read it. The split matters because validators typically run on a parsed structure while the fetch is performed by a client, a proxy, a resolver, or a shell-out, and each of those may re-derive the host, re-resolve it, apply its own redirect policy, or interpret a scheme the validator never modelled. The field rule is that the convincing evidence names the component: the fetch is proven by a callback or a response, and the parser disagreement is proven by the validator accepting a value the fetcher then sends somewhere else.

- *Disproof:* The claim is false when the same component performs both the parse and the fetch and there is no intervening layer - a single library that validates the parsed URL and then dials the same URL object has no differential by construction, and a payload that appears in the outbound request at the intended host is the end of the question. It also fails when the evidence is an actual callback from a server only the attacker controls: that proves the fetch happened, whatever the validator thought. And a parser that rejects the payload outright with an error the application propagates is a genuine block, which is the case the rule is warning you not to mistake for one.
- *Evidence:* high_confidence — [go.dev](https://go.dev/src/net/url/url.go); [wicg.github.io](https://wicg.github.io/private-network-access/)

**A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.**

Two distinct controls are involved: a validator that inspects the supplied URL, and the HTTP client that follows redirects and resolves DNS. A validator rejecting internal addresses and then being defeated by a redirect is a redirect-following defect; a fetcher whose hostname resolves to an internal address after validation is a DNS-resolution defect. Each has a different remediation, so conflating them lets a client patch the validator and leave the bypass intact.

- *Disproof:* If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc9110); [portswigger.net](https://portswigger.net/web-security/ssrf)

**An SSRF filter that restricts the scheme on the initial URL is not a control on the transfer if the client follows redirects, because the protocol allow-list applies to the follow-up request and is a separate setting from the initial one.**

libcurl makes the two-control distinction explicit in its API. CURLOPT_PROTOCOLS_STR takes a comma-separated list of case-insensitive protocol names and limits which protocols may be used in the transfer; by default libcurl accepts all protocols it was built with support for. CURLOPT_REDIR_PROTOCOLS_STR exists separately because that list limits what protocols may be used in a transfer that it follows to in a redirect when CURLOPT_FOLLOWLOCATION is enabled, and by default libcurl allows HTTP, HTTPS, FTP and FTPS on redirects. So an application that carefully sets CURLOPT_PROTOCOLS_STR to http,https and enables redirect-following has expressed two different intentions, and the second one is a default that permits four schemes. The field test is to send your own 302 to a scheme the initial filter forbids and see whether the client reaches it - that distinguishes an SSRF filter that covers the transfer from one that only covers the string it was handed.

- *Disproof:* The claim is false when CURLOPT_REDIR_PROTOCOLS_STR is set to match the initial list, since the documentation is explicit that protocols denied by CURLOPT_PROTOCOLS_STR are not overridden by it, so a correctly configured pair holds for both the first request and every redirect. It is also false where the client does not follow redirects at all, or follows them with the scheme re-validated against the same allow-list by application code on each hop. And in runtimes other than libcurl the equivalent controls differ - Go's http.Client delegates redirect policy to a CheckRedirect hook that the caller must supply, so the gap here is specific to clients whose redirect scheme policy has a permissive default.
- *Evidence:* high_confidence — [curl.se](https://curl.se/libcurl/c/CURLOPT_PROTOCOLS_STR.html); [pkg.go.dev](https://pkg.go.dev/net/http)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An SSRF filter that resolves the hostname and checks the IP once, before connecting, is defeated by DNS rebinding, because the address the client connects to is resolved again and may differ.**

The Private Network Access explainer states the design requirement in the negative form: the mitigation operates upon the IP address which the user agent actually connects to when loading a particular resource, and this check MUST be performed for each new connection made, as DNS rebinding attacks may otherwise trick the user agent into revealing information it shouldn't. That 'for each new connection' is the whole bypass. A server-side analogue is a filter that validates the resolved address at request time and then performs a separate connect by hostname, giving the attacker two resolutions to win - a public address for the check and a private address for the connection, with a TTL low enough that the second answer differs. The hunter's technique is a low-TTL record alternating between a public address and 127.0.0.1 or a link-local address, and the pass condition is a callback or a response that only a private service could have produced.

- *Disproof:* The claim is false when the filter pins the address: a client that connects to the validated IP with a Host header set separately, or one that resolves once and hands the socket to the request, has no second resolution to attack, and the check and the connection agree by construction. It also fails where the environment re-resolves or re-validates on every connection at a layer below the application - a proxy or egress gateway that performs its own resolution and address-space check, which is the architecture the Private Network Access document is describing on the browser side. And the attack requires an attacker-controlled DNS name that alternates, which many managed environments defeat by resolving once per process or by refusing low-TTL answers from untrusted resolvers.
- *Evidence:* high_confidence — [go.dev](https://go.dev/src/net/url/url.go); [wicg.github.io](https://wicg.github.io/private-network-access/)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An SSRF that the application's own filters do not recognise as reaching a metadata endpoint still yields instance credentials, which are then spent with the ambient authority of the hosting application identity rather than the anonymous attacker.**

The published Red Agent case is a worked example of the whole assembly: it uncovered a multi-step attack chain allowing ssrf-to-local-file-read on a GCP Cloud Run API, and it probed the url parameter with authority-confusion and fragment techniques precisely because the naive metadata request was validated. The generic statement of why SSRF escalates is that an attacker can abuse the server's trusted network position to force it into interacting with internal-only services, querying cloud metadata endpoints to extract credentials, or reading local files through alternative URI schemes. The second half of the chain is the credential's scope: application identities typically carry broad access, so the harvest is spent with the app's own authority. Vendor post-exploitation telemetry on a widely exploited server-side flaw confirms the destination half as well, with operators dumping LSASS memory to harvest credentials rather than acting locally.

- *Disproof:* Refuted when the metadata service requires an identity-bound header such as an instance identity document or when the workload runs with no attached service account; the fetch then returns nothing an attacker can redeem.
- *Evidence:* high_confidence — [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/threat-brief-owassrf/); [wiz.io](https://www.wiz.io/blog/red-agent-pov-ssrf)

**An SSRF whose scheme is attacker-chained into file://, gopher://, or dict:// upgrades a read-only web fetch into local file access or arbitrary-protocol byte delivery.**

Once request initiation is confirmed, determine whether the scheme is restricted to http/https. If the fetcher honors arbitrary schemes, chain from HTTP to file:// for local file read, and to gopher:// or dict:// for crafting arbitrary bytes toward internal services speaking line- or field-oriented plaintext protocols, which is how cache poisoning and CRLF injection against internal services are reached. Verify the scheme is rejected before claiming the chain.

- *Disproof:* If the fetcher rejects every non-HTTP scheme with an error and never dereferences them, the scheme-abuse chain is unavailable.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.**

Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

- *Disproof:* If the destination is restricted to an allowlist of external hosts and the response is never returned, none of those internal targets are reachable from the endpoint.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

**A server-side request that reaches the metadata endpoint yields tokens minted for the VM's managed identity, so the impact of that SSRF is credential takeover of every identity attached to the VM rather than plain information disclosure.**

A server-side request that reaches the metadata endpoint yields tokens minted for the VM's managed identity, so the impact of that SSRF is credential takeover of every identity attached to the VM rather than plain information disclosure.

HackTricks reference: Cloud SSRF (pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md)

- *Disproof:* Refuted if the metadata request from the SSRF sink returns no token, or hands back a token naming an identity that is not attached to the target VM and is rejected when used.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/441.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md)

**Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.**

Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

- *Disproof:* If the reachable functionality only issues read-only requests and cannot alter state on the internal service, the impact stops at reading.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

**The severity of a server-side request forgery finding comes from the network position and trust the application lends the forged request, not from the request existing at all, so a hunter must show what the server-side fetch reaches that the client origin cannot.**

The severity of a server-side request forgery finding comes from the network position and trust the application lends the forged request, not from the request existing at all, so a hunter must show what the server-side fetch reaches that the client origin cannot.

HackTricks reference: request forgery csrf and ssrf (https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf.md)

- *Disproof:* If the server-side fetch is shown to originate from the attacker's own network position, or to reach nothing the client origin could not already reach itself, the leverage-based impact claim fails.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/441.html); [oreobiscuit.gitbook.io](https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf.md); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

**SSRF is also an attribution and abuse-laundering primitive: requests appear to originate from the victim organization.**

Frame impact around what the server can reach on the attacker's behalf: spoofed source IP toward third parties, internal-only protocols and ports, and possible command execution in some configurations. Any request your server makes toward a host you do not own is a third-party interaction you cannot clean up, so prove impact against hosts you control or the target's own internal range, and stop before spraying third-party infrastructure.

- *Disproof:* If the server is strictly limited to a small allowlisted set of first-party hosts with redirects disabled, onward third-party abuse and attribution laundering are not reachable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
