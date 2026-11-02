# Server-Side Request Forgery

> surface: `web` · CWE: CWE-918 · OWASP: A10:2021
> maturity: **mature** — 50 items, 42 supported, 19 FP rules, 1 chains

The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.

**Aliases:** ssrf, server side request forgery, blind ssrf, cloud metadata ssrf

## Prerequisite

- **A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.**  
  `high_confidence` · score 0.8255 · disproved by: Refuted if a registered callback value is never fetched by the server - it only appears in outbound mail or client-side rendering, or registration is pinned to a fixed allowlisted host.
  sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
- **Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.**  
  `high_confidence` · score 0.8115 · disproved by: If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>

## Signal

- **Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.**  
  `high_confidence` · score 0.853 · disproved by: Refuted if the same error class is returned for an empty or syntactically invalid URL that can never produce an outbound request, meaning the errors track input validation rather than a request leaving the host.
  sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
- **A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.**  
  `high_confidence` · score 0.853 · disproved by: If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
- **An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.**  
  `high_confidence` · score 0.8515 · disproved by: A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
- **A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.**  
  `high_confidence` · score 0.824 · disproved by: A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
- **An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.**  
  `under_review` · score 0.7655 · disproved by: A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
- **A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.**  
  `under_review` · score 0.738 · disproved by: A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>

## Technique

- **Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.**  
  `high_confidence` · score 0.885 · disproved by: If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.**  
  `high_confidence` · score 0.8815 · disproved by: If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
- **SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.**  
  `high_confidence` · score 0.8805 · disproved by: If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
  sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://portswigger.net/web-security/ssrf>
- **Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.**  
  `high_confidence` · score 0.8805 · disproved by: If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
  sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://portswigger.net/web-security/ssrf>
- **A server-side request forgery is confirmed when a URL supplied by the client is fetched by the server and its response body is reflected back to the client.**  
  `high_confidence` · score 0.873 · disproved by: Refuted when the server performs the fetch but returns no attacker-observable signal (status, timing, or body difference), in which case no request forgery is provable.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/oouch-write-up.md> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/travel-write-up.md>
- **The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.**  
  `under_review` · score 0.872 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
- **When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.**  
  `high_confidence` · score 0.863 · disproved by: Refuted if requesting a token from the metadata endpoint without naming an identity succeeds and returns a token for the intended user-assigned identity, or if the platform configuration endpoint lists no identities at all.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md>
- **Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.**  
  `high_confidence` · score 0.853 · disproved by: Refuted if the final artifact is byte-identical whether the callback URL is tester-controlled or replaced with an unreachable one, or the fetched body is never stored or re-rendered anywhere visible.
  sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
- **Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.**  
  `high_confidence` · score 0.853 · disproved by: Refuted if a filename containing encoded newlines adds no headers to the outbound request because the request line is percent-encoded, or if the metadata endpoint answers identically regardless of the injected headers.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
- **A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.**  
  `high_confidence` · score 0.853 · disproved by: Refuted if changing the SNI value does not change the host the server connects to - behaviour is identical for an attacker SNI, a bogus SNI and no SNI at all.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
- **Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.**  
  `high_confidence` · score 0.8255 · disproved by: Refuted when the automated sweep reports no SSRF yet a manual request to the same bypassed URL with an attacker-controlled host does produce an outbound callback, which shows the tool missed a live sink.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md>
- **SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header**  
  `under_review` · score 0.817 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
- **Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ).**  
  `under_review` · score 0.7895 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
- **The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.**  
  `under_review` · score 0.7555 · disproved by: If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>

## Test

- **To decide this case, observe: A payload rejected by a strict allowlist comparison is not a bypass even if a client would have parsed it differently.**  
  `high_confidence` · score 0.8965 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.validation.identify_which_component_parsed) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **To decide this case, observe: A 4xx, a validation error, or a silent drop with no collaborator traffic is the expected outcome of working filtering.**  
  `high_confidence` · score 0.8665 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.rejected_payload_without_egress) states the full boundary.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf>
- **To decide this case, observe: Without a readable response you cannot show what was retrieved, so keep the finding scoped to 'server makes attacker-directed requests' and state the unproven parts explicitly.**  
  `high_confidence` · score 0.853 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.oast_callback_is_not_exfil) states the full boundary.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>

## Validation

- **A bypass is only proven when the component that actually performs the fetch resolved a different host than the validating component approved.**  
  `high_confidence` · score 0.924 · disproved by: If the fetch connects to the allowlisted host for every variant, the allowlist held and no bypass occurred.
  sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **A DNS lookup with no follow-up HTTP request indicates the request was blocked by network filtering, not that the SSRF is a false positive.**  
  `high_confidence` · score 0.839 · disproved by: If inbound HTTP requests to the same unique domain do arrive under identical egress conditions, the failure was transient and the DNS-only pattern is not explained by filtering.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>
- **A filter that rejects a named set of internal addresses is weaker than an address-space check, because every address belongs to one of three spaces and the classification is defined by what the address means rather than by its literal value.**  
  `high_confidence` · score 0.783 · disproved by: The claim does not mean a blocklist cannot be sufficient: in a deployment with a small, known internal surface, a deny-list covering every internal range plus a default-deny egress rule at the network layer is a real control, and the browser-side proposal itself is candid that it merely mitigates attacks against private web services and cannot fully solve them. It also fails as a claim of a specific finding if the untested range is not in the target's address plan - a 10.0.0.0/8 that the environment has no reason to use. The disproof has to come from an address that actually resolves and connects to something, not from a range in a table.
  sources: <https://pkg.go.dev/net/http> · <https://wicg.github.io/private-network-access/>

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
- **A payload that a URL parser accepts with the host you intended does not prove the component that performs the fetch will use that host, because parsing and fetching are separate steps and are frequently performed by different code.**  
  `high_confidence` · score 0.838 · disproved by: The claim is false when the same component performs both the parse and the fetch and there is no intervening layer - a single library that validates the parsed URL and then dials the same URL object has no differential by construction, and a payload that appears in the outbound request at the intended host is the end of the question. It also fails when the evidence is an actual callback from a server only the attacker controls: that proves the fetch happened, whatever the validator thought. And a parser that rejects the payload outright with an error the application propagates is a genuine block, which is the case the rule is warning you not to mistake for one.
  sources: <https://go.dev/src/net/url/url.go> · <https://wicg.github.io/private-network-access/>
- **A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.**  
  `high_confidence` · score 0.814 · disproved by: If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://datatracker.ietf.org/doc/html/rfc9110> · <https://portswigger.net/web-security/ssrf>
- **An SSRF filter that restricts the scheme on the initial URL is not a control on the transfer if the client follows redirects, because the protocol allow-list applies to the follow-up request and is a separate setting from the initial one.**  
  `high_confidence` · score 0.8105 · disproved by: The claim is false when CURLOPT_REDIR_PROTOCOLS_STR is set to match the initial list, since the documentation is explicit that protocols denied by CURLOPT_PROTOCOLS_STR are not overridden by it, so a correctly configured pair holds for both the first request and every redirect. It is also false where the client does not follow redirects at all, or follows them with the scheme re-validated against the same allow-list by application code on each hop. And in runtimes other than libcurl the equivalent controls differ - Go's http.Client delegates redirect policy to a CheckRedirect hook that the caller must supply, so the gap here is specific to clients whose redirect scheme policy has a permissive default.
  sources: <https://curl.se/libcurl/c/CURLOPT_PROTOCOLS_STR.html> · <https://pkg.go.dev/net/http>

## Evidence

- **SSRF is proven when a request carrying an attacker-chosen URL returns in the response body content that only the server could have fetched, because that content arrived from an address the tester has no route to.**  
  `high_confidence` · score 0.909 · disproved by: The claim is false when the tester can reach the same address directly, so the response proves nothing about the server's egress; when the returned content is a generic error page or an application-generated message rather than the target resource's bytes; when the fetch was served from a cache populated by an earlier request rather than performed for this one; or when the endpoint never issued the request at all because its own validation rejected the URL before any network activity.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://httpd.apache.org/docs/2.4/mod/mod_proxy.html>
- **Blind SSRF is proven when a request naming a server-side URL causes an outbound connection, a DNS lookup or an HTTP request to a host the tester controls, carrying a token unique to that one request, which is the only artifact available when the response is not reflected.**  
  `high_confidence` · score 0.9065 · disproved by: The claim is false when no callback arrives at the controlled host, which leaves the case unproven rather than disproven; when the callback host was unreachable for reasons unrelated to the payload; when the callback carries no token unique to the request, so it cannot be attributed; or when the application's normal background traffic reaches the same host, making the event unattributable. It is also false when the target environment has no egress path to the tester, which converts the missing callback into an untestable negative.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://httpd.apache.org/docs/2.4/mod/mod_proxy.html>
- **A denial-of-filtering artifact is a request for an address in the range IETF reserves for documentation, 192.0.2.0/24 and its two siblings, that is still forwarded: those blocks are never routable on the public internet, so any answer at all can only have come from a network segment the tester cannot see.**  
  `high_confidence` · score 0.8905 · disproved by: The claim is false where the documented ranges are filtered before any network activity, in which case the observation is a working control and not a gap. It is also false where the tester actually has a route to the address, where the environment routes those ranges because it is itself a test lab and so emits a response the tester could have obtained directly, and where the response is generated by the application as an error page rather than by a downstream service. Timeouts and refusals on these addresses prove nothing either way and must not be reported as a negative finding.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://www.rfc-editor.org/rfc/rfc5737.txt>
- **SSRF is proven at maximum severity when the server fetches its own instance metadata service and returns the temporary security credentials bound to the instance role, because those credentials are minted for the server and are useless to the tester from outside.**  
  `high_confidence` · score 0.863 · disproved by: The claim is false when the metadata service returns no credentials - no role is attached to the instance, or the response is a document with no credential fields present, which AWS documents explicitly as the otherwise-not-present case. It is also false where the response came from a cache or a decoy rather than the live metadata service, where the endpoint is not actually the cloud metadata address but an unrelated host the tester pointed at, and where a session-oriented metadata version rejected the request outright - a token requirement is a real control, not a gap.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>

## Impact

- **Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.**  
  `high_confidence` · score 0.8815 · disproved by: If the destination is restricted to an allowlist of external hosts and the response is never returned, none of those internal targets are reachable from the endpoint.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
- **A server-side request that reaches the metadata endpoint yields tokens minted for the VM's managed identity, so the impact of that SSRF is credential takeover of every identity attached to the VM rather than plain information disclosure.**  
  `high_confidence` · score 0.863 · disproved by: Refuted if the metadata request from the SSRF sink returns no token, or hands back a token naming an identity that is not attached to the target VM and is rejected when used.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md>
- **Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.**  
  `high_confidence` · score 0.854 · disproved by: If the reachable functionality only issues read-only requests and cannot alter state on the internal service, the impact stops at reading.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
- **The severity of a server-side request forgery finding comes from the network position and trust the application lends the forged request, not from the request existing at all, so a hunter must show what the server-side fetch reaches that the client origin cannot.**  
  `high_confidence` · score 0.8515 · disproved by: If the server-side fetch is shown to originate from the attacker's own network position, or to reach nothing the client origin could not already reach itself, the leverage-based impact claim fails.
  sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf.md>
- **SSRF is also an attribution and abuse-laundering primitive: requests appear to originate from the victim organization.**  
  `high_confidence` · score 0.8255 · disproved by: If the server is strictly limited to a small allowlisted set of first-party hosts with redirects disabled, onward third-party abuse and attribution laundering are not reachable.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
- **Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.**  
  `under_review` · score 0.7555 · disproved by: If the destination is restricted to an allowlist of external hosts and the response is never returned, none of those internal targets are reachable from the endpoint.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
- **Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.**  
  `under_review` · score 0.728 · disproved by: If the reachable functionality only issues read-only requests and cannot alter state on the internal service, the impact stops at reading.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>

## Variant

- **Where a request parameter takes an arbitrary URL, feeding it a loopback admin address and observing the server act on the fetched content is the test that turns that parameter into an SSRF sink and the entry point for escalation to code execution.**  
  `high_confidence` · score 0.853 · disproved by: Refuted when the loopback address in that parameter is rejected outright with the same error as a malformed value and no server-side fetch of the internal address ever occurs.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md>
- **Clearing one read-only callback handler does not clear the SSRF surface, because other registered backends in the same registry may still accept writes, so every registered handler has to be exercised before the feature is called safe.**  
  `high_confidence` · score 0.8255 · disproved by: Refuted if enumerating the registry returns only read-only handlers and no create/write entry point exists anywhere in the callback registration.
  sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>

## Bypass

- **An SSRF filter that resolves the hostname and checks the IP once, before connecting, is defeated by DNS rebinding, because the address the client connects to is resolved again and may differ.**  
  `high_confidence` · score 0.838 · disproved by: The claim is false when the filter pins the address: a client that connects to the validated IP with a Host header set separately, or one that resolves once and hands the socket to the request, has no second resolution to attack, and the check and the connection agree by construction. It also fails where the environment re-resolves or re-validates on every connection at a layer below the application - a proxy or egress gateway that performs its own resolution and address-space check, which is the architecture the Private Network Access document is describing on the browser side. And the attack requires an attacker-controlled DNS name that alternates, which many managed environments defeat by resolving once per process or by refusing low-TTL answers from untrusted resolvers.
  sources: <https://go.dev/src/net/url/url.go> · <https://wicg.github.io/private-network-access/>

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

- **Hypothesis:** The client bundle references URL-accepting parameters for import, webhook and avatar features, therefore the application is vulnerable to SSRF
  - **Invalidated by:** The consuming endpoints require an authenticated session. Unauthenticated the parameter was ignored entirely - application shell or 404, no server-side fetch. No outbound request occurred
  - **Rule:** A URL parameter proves SSRF only when the SERVER acts on it. Probe it unauthenticated and look for a DNS or HTTP effect attributable to your input; an ignored parameter is not SSRF, and a feature that exists only behind a session you cannot obtain is untested rather than vulnerable

## Related classes (via chains)

- `api_trust` API-to-API Trust Failures (3 chains)
