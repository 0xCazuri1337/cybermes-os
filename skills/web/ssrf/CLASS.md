<!-- GENERATED from db/wks.db — do not edit -->
# Server-Side Request Forgery

## Definition

The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.

- **CWE:** CWE-918
- **OWASP:** A10:2021
- **Surface:** web
- **Aliases:** ["ssrf", "server side request forgery", "blind ssrf", "cloud metadata ssrf"]

Canonical home for `ssrf`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**CWE-918 defines SSRF as a weakness where a web server receives a URL from an upstream component and retrieves its contents without sufficiently ensuring the request is sent to the expected destination.**

CWE-918's canonical definition states: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination." The weakness is classified at Base abstraction and is actively mapped to real-world vulnerabilities (CWE lists 6602+ related vulnerabilities per cvedatabase). This makes SSRF a mature, well-mapped weakness rather than a theoretical or edge-case defect.

*Disproof:* A claim that SSRF is only a theoretical flaw with no authoritative mapping is refuted by CWE's own Vulnerability Mapping Notes, which explicitly state "Vulnerability Mapping: ALLOWED" and that the Base-level entry "is a preferred level of abstraction for mapping to the root causes of vulnerabilities".

**A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.**

A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.

HackTricks reference: SSRF Vulnerable Platforms (pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

*Disproof:* Refuted if a registered callback value is never fetched by the server - it only appears in outbound mail or client-side rendering, or registration is pinned to a fixed allowlisted host.

**Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.**

Determine the app server's egress posture before rating impact. Infrastructure often permits outbound DNS while filtering outbound HTTP, so a blind SSRF may be real but reach only a resolver. If a network-layer restriction exists the finding is a defense-in-depth gap rather than a confirmed fetch. Record which of DNS resolution, TCP connect, and HTTP response actually occurred; these are three distinct proofs with three different severities.

*Disproof:* If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A classic SSRF signal is an application that fetches a user-supplied URL and returns its contents; attackers exploit trust relationships so that requests to localhost or internal IPs are granted access the attacker could never reach directly.**

PortSwigger explains that SSRF allows the attacker to cause the server-side application to make requests to an unintended location, typically internal-only services. The trust relationship is the signal: when a request to http://localhost/admin is served because "the request to the /admin URL comes from the local machine, the normal access controls are bypassed." The same mechanism applies to back-end systems on private IPs such as http://192.168.0.68/admin. Impact includes unauthorized access to data within the organization, and in some situations arbitrary command execution.

*Disproof:* A claim that SSRF always requires the attacker to see the back-end response in the HTTP response to the client is refuted by blind SSRF, where the response is not returned to the front end, yet the server still makes the request.

**An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.**

An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.

HackTricks reference: blind ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md)

*Disproof:* A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.

**Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.**

Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.

HackTricks reference: SSRF Vulnerable Platforms (pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

*Disproof:* Refuted if the same error class is returned for an empty or syntactically invalid URL that can never produce an outbound request, meaning the errors track input validation rather than a request leaving the host.

**A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.**

A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.

HackTricks reference: blind ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md)

*Disproof:* A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.

**An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.**

An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.

HackTricks reference: blind ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md)

*Disproof:* A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.

**A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.**

A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.

HackTricks reference: blind ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md)

*Disproof:* A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.

**A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.**

Generate a unique per-payload domain on a collaborator service, embed it in each candidate URL field (including nested JSON/XML values and secondary fetches), then monitor for DNS and HTTP interactions correlated to that exact token. Correlating a unique token per request avoids false positives from scanners and crawlers. Only an inbound HTTP request counts as proof; a DNS lookup alone is a weaker, separately-graded signal.

*Disproof:* If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.

**SSRF is a live enterprise threat vector used to reach cloud instance metadata services (AWS IMDS, GCP, Azure), harvesting temporary IAM credentials that grant unauthorized access to cloud resources, and it is mapped by MITRE to the T1190 initial-access technique.**

CraftedSignal's threat feed describes the attack chain: the attacker exploits an SSRF in a public-facing app (Nginx, Apache, IIS, Traefik) to make the web server connect to an internal metadata endpoint such as http://169.254.169.254/latest/meta-data/, obtains temporary IAM role credentials and API tokens, and exfiltrates them to compromise cloud resources. MITRE T1190 treats SSRF-bearing applications as entry points: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network," and notes that on cloud/containerized infrastructure, exploiting it may lead to compromise of the underlying instance or container, including access to cloud or container APIs. The feed also lists detection guidance: deploy a Sigma rule to detect metadata endpoints and enforce IMDSv2.

*Disproof:* A claim that SSRF's only business impact is reading data from the vulnerable application (low severity) is refuted by both sources: CraftedSignal states the stolen credentials enable unauthorized access to cloud resources, data exfiltration, privilege escalation, and lateral movement, while MITRE states exploitation may lead to compromise of the underlying instance or container, including access to cloud/container APIs.

**Blind SSRF is proven when a request naming a server-side URL causes an outbound connection, a DNS lookup or an HTTP request to a host the tester controls, carrying a token unique to that one request, which is the only artifact available when the response is not reflected.**

When the endpoint gives nothing back, the fetch itself is the observable: the server's own network position is what gets weaponised, so the tester supplies a destination it monitors and waits for the connection. This is the disproof-of-blindness instrument, and it is also what distinguishes a real server-side fetch from an application that merely validates the string - an application that parses the URL and rejects it produces no callback at all, while one that opens a connection produces one within milliseconds. The token in the URL path ties the event to the request that caused it, which matters because a scheduled job or health check could otherwise produce an unsolicited connection that a careless tester would count as their own. OWASP notes the difficulty honestly: where no feedback is possible, confirmation has to come from outside the response entirely.

*Disproof:* The claim is false when no callback arrives at the controlled host, which leaves the case unproven rather than disproven; when the callback host was unreachable for reasons unrelated to the payload; when the callback carries no token unique to the request, so it cannot be attributed; or when the application's normal background traffic reaches the same host, making the event unattributable. It is also false when the target environment has no egress path to the tester, which converts the missing callback into an untestable negative.

**SSRF is proven at maximum severity when the server fetches its own instance metadata service and returns the temporary security credentials bound to the instance role, because those credentials are minted for the server and are useless to the tester from outside.**

This is the finding that converts an SSRF from information disclosure into account compromise, and the artifact is a credential document the tester could not have obtained any other way. Cloud instance metadata is the canonical target because the endpoint is reachable from the workload itself and is intended only for on-instance callers, so the SSRF request is reaching a service that was never exposed to the public internet. AWS's own documentation of the metadata category shows why the result is live rather than informational: the security-credentials category holds the temporary security credentials associated with the instance role. A hunter reports this by quoting the returned credential fields and noting that they were obtained through the application, not from the instance directly, which establishes the network path that made them reachable.

*Disproof:* The claim is false when the metadata service returns no credentials - no role is attached to the instance, or the response is a document with no credential fields present, which AWS documents explicitly as the otherwise-not-present case. It is also false where the response came from a cache or a decoy rather than the live metadata service, where the endpoint is not actually the cloud metadata address but an unrelated host the tester pointed at, and where a session-oriented metadata version rejected the request outright - a token requirement is a real control, not a gap.

**A denial-of-filtering artifact is a request for an address in the range IETF reserves for documentation, 192.0.2.0/24 and its two siblings, that is still forwarded: those blocks are never routable on the public internet, so any answer at all can only have come from a network segment the tester cannot see.**

The trick is to choose probe targets whose reachability is known a priori rather than discovered. IETF reserved three IPv4 blocks specifically for use in documentation, and RFC 5737 says addresses in them should not be used on the public Internet, so an HTTP server's timeout or connection refusal on 192.0.2.0 tells the tester nothing, but a service that answers - a default landing page, a banner, a proxy error naming the internal hop - is unambiguous evidence that the request left the application and entered a segment the tester has no route to. This is what makes the probe conclusive rather than suggestive: it does not depend on the tester having a blocked address to try, and it avoids the common false positive of a request that was never sent because a deny-list rejected it on a recognisable pattern. Each probe is a single GET, and the internal-address evidence is what the response body or the callback delivers.

*Disproof:* The claim is false where the documented ranges are filtered before any network activity, in which case the observation is a working control and not a gap. It is also false where the tester actually has a route to the address, where the environment routes those ranges because it is itself a test lab and so emits a response the tester could have obtained directly, and where the response is generated by the application as an error page rather than by a downstream service. Timeouts and refusals on these addresses prove nothing either way and must not be reported as a negative finding.

**SSRF is proven when a request carrying an attacker-chosen URL returns in the response body content that only the server could have fetched, because that content arrived from an address the tester has no route to.**

The evidentiary weight comes entirely from the address space: the tester asks the server to fetch something the tester provably cannot reach, and the substance of that resource comes back in the response. OWASP's API guidance makes the split explicit - basic SSRF, where the response is returned to the attacker, is easier to exploit than blind SSRF in which there is no feedback on whether the attack succeeded - which is precisely why a reflected body is the artifact to capture and a blind one has to be argued out-of-band instead. CWE-441 supplies the underlying property: the product forwards the request without preserving its original source, so it appears to be the source and acts as a proxy. A hunter makes the proof tight by fetching, through the server, a resource whose body embeds a token generated for that one request; a matching token in the response ties the bytes to that fetch and rules out caching or coincidence.

*Disproof:* The claim is false when the tester can reach the same address directly, so the response proves nothing about the server's egress; when the returned content is a generic error page or an application-generated message rather than the target resource's bytes; when the fetch was served from a cache populated by an earlier request rather than performed for this one; or when the endpoint never issued the request at all because its own validation rejected the URL before any network activity.

## Exploitation

**Blind SSRF is reliably detected using out-of-band (OAST) techniques: trigger an HTTP request to a domain the attacker controls and monitor for any inbound request from the target.**

PortSwigger states that the most reliable way to detect blind SSRF vulnerabilities is using out-of-band (OAST) techniques. The tester generates unique domain names (e.g., with Burp Collaborator), injects them into the target, and monitors for interactions. If an incoming HTTP request is observed coming from the application, then it is vulnerable to SSRF. Blind SSRF also enables internal IP sweeping to detect vulnerabilities on internal servers, and can be chained by inducing the application to connect to a system under the attacker's control and return malicious responses that may achieve remote code execution in the application infrastructure.

*Disproof:* A claim that a DNS lookup for the collaborator domain is itself conclusive evidence of SSRF is refuted by PortSwigger's note: it is common to observe a DNS look-up for the supplied Collaborator domain without a subsequent HTTP request, because the HTTP request may be blocked by network-level filtering.

**The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.**

Demonstrative Examples 
 
 
 
 
 Example 1 
 
 
 This code intends to receive a URL from a user, access the URL, and return the results to the user. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 $url = $_GET['url']; # User-controlled input 
 
 # Fetch the content of the provided URL 
 $response = file_get_contents($url); 
 echo $response; 
 
 
 
 
 
 
 
 
 
 
 
 
 The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions. This allows an attacker to request internal or restricted resources within the server's network, such as internal admin panels, cloud metadata endpoints, or local services running on localhost. 
 
 
 
 
 
 
 
 
 (good code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 # Define allowed URLs (or domains) $allowed_urls = [ 'https://example.com/data.json', 'https://api.example.com/info', ]; # Get the user

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because i”) does not occur under a test that isolates that control.

**SSRF in LLM application development framework because the URL retriever allows connections to local addresses.**

to understand the variety of ways in which this
 weakness can be introduced. It is not a complete list of all CVEs that are related to this CWE entry. 
 
 
 
 
 Reference 
 Description 
 
 
 
 
 
 
 
 CVE-2026-33626 
 
 
 
 
 SSRF in LLM toolkit accesses arbitrary URLs for images, as exploited in the wild in April 2026 to conduct port scanning [ REF-1519 ] 
 
 
 
 
 
 
 
 CVE-2024-3095 
 
 
 
 
 SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header 
 
 
 
 
 
 
 
 CVE-2023-32786 
 
 
 
 
 Chain: LLM integration framework has prompt injection
 ( CWE-1427 ) that allows an attacker to force the service to retrieve
 data from an arbitrary URL, essentially providing SSRF ( CWE-918 ) and
 potentially injecting content into downstream tasks. 
 
 
 
 
 
 
 
 CVE-2021-26855 
 
 
 
 
 Server Side Request Forgery (SSRF) in mail server, as exploited in

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“SSRF in LLM application development framework because the URL retriever allows c”) does not occur under a test that isolates that control.

**Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ).**

URL, essentially providing SSRF ( CWE-918 ) and
 potentially injecting content into downstream tasks. 
 
 
 
 
 
 
 
 CVE-2021-26855 
 
 
 
 
 Server Side Request Forgery (SSRF) in mail server, as exploited in the wild per CISA KEV. 
 
 
 
 
 
 
 
 CVE-2021-21973 
 
 
 
 
 Server Side Request Forgery in cloud platform, as exploited in the wild per CISA KEV. 
 
 
 
 
 
 
 
 CVE-2016-4029 
 
 
 
 
 Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ). 
 
 
 
 
 
 
 
 CVE-2002-1484 
 
 
 
 
 Web server allows attackers to request a URL from another server, including other ports, which allows proxied scanning. 
 
 
 
 
 
 
 
 CVE-2004-2061 
 
 
 
 
 CGI script accepts and retrieves incoming URLs. 
 
 
 
 
 
 
 
 CVE-2010-1637 
 
 
 
 
 Web-based mail program allows internal network scanning using a modified POP3 port number. 
 
 
 
 
 
 
 
 CVE-

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: incorrect validation of intended decimal-based IP address format ( CWE-12”) does not occur under a test that isolates that control.

**A server-side request forgery is confirmed when a URL supplied by the client is fetched by the server and its response body is reflected back to the client.**

In practice on HTB this shows up as: ### Server-side Request Forgery \(SSRF\)
Next, I needed to get the admin to link his account to mine in order to escalate my privileges. I went back to the `http://consumer.oouch.htb:5000/contact` page, and sent the admin the link with my authorization token request link, which was already activated through the POST message earlier. All I needed was for the admin to click the link to connect our accounts. This was an example of an attack called [Server-side Request Forgery \(SSRF\)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
> Screenshot omitted: the original GitBook asset is not present in this repository.

Write-up provenance: zweilosec/htb-writeups :: linux-machines/hard/oouch-write-up.md (4663 words, classified network).

*Disproof:* Refuted when the server performs the fetch but returns no attacker-observable signal (status, timing, or body difference), in which case no request forgery is provable.

**Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.**

From the server, request the link-local metadata address and the cloud vendor DNS name for the metadata service, including IPv6 forms for IPv6-capable instances. Metadata keys commonly expose instance identity, network config, and user-supplied data or credentials written there. Report metadata reachability as a finding with the exact endpoint that answered and the key names visible; do not retrieve or exfiltrate secret values.

*Disproof:* If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.

**Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.**

Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.

HackTricks reference: SSRF Vulnerable Platforms (pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md)

*Disproof:* Refuted if the final artifact is byte-identical whether the callback URL is tester-controlled or replaced with an unreachable one, or the fetched body is never stored or re-rendered anywhere visible.

**When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.**

When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.

HackTricks reference: Cloud SSRF (pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md)

*Disproof:* Refuted if requesting a token from the metadata endpoint without naming an identity succeeds and returns a token for the intended user-assigned identity, or if the platform configuration endpoint lists no identities at all.

**Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.**

Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.

HackTricks reference: SSRF (Server Side Request Forgery) (pentesting-web/ssrf-server-side-request-forgery/README.md)

*Disproof:* Refuted if a filename containing encoded newlines adds no headers to the outbound request because the request line is percent-encoded, or if the metadata endpoint answers identically regardless of the injected headers.

**The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.**

The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

*Disproof:* If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.

**A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.**

A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.

HackTricks reference: SSRF (Server Side Request Forgery) (pentesting-web/ssrf-server-side-request-forgery/README.md)

*Disproof:* Refuted if changing the SNI value does not change the host the server connects to - behaviour is identical for an attacker SNI, a bogus SNI and no SNI at all.

**Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.**

Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.

HackTricks reference: AEM - Adobe Experience Cloud (network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md)

*Disproof:* Refuted when the automated sweep reports no SSRF yet a manual request to the same bypassed URL with an attacker-controlled host does produce an outbound callback, which shows the tool missed a live sink.

**The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.**

The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

*Disproof:* If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.

**SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.**

Probe loopback aliases and private ranges from the app server: 127.0.0.1, localhost, alternative IP encodings of 127.0.0.1, RFC1918 targets, and alternate ports where an admin interface listens. High-value targets are components that treat a request originating locally as trusted, including management interfaces, DR-only unauthenticated admin paths, and sidecar APIs. Response differences (status, body length, timing) reveal reachability even when the body is filtered.

*Disproof:* If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.

**Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.**

Probe parser differentials: userinfo tricks such as https://expected-host:pass@evil-host, fragments such as https://evil-host#expected-host, suffix matching such as https://expected-host.evil-host, percent- and double-encoding, and case variation. Also test rare IP literal forms (dword, octal, hex, short forms) and IPv6 bracket literals. The host production is genuinely ambiguous, so implementations legitimately disagree; judge each payload on which component parsed it.

*Disproof:* If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.

## Variations

**SSRF filters are routinely bypassed using alternative IP representations of loopback, URL-encoding or case variation, open-redirect chains, credential embedding, URL fragments, and fully-qualified DNS hierarchy tricks.**

PortSwigger documents that blacklist defenses against SSRF are commonly circumvented with: alternative IP representations of 127.0.0.1 such as 2130706433, 017700000001, or 127.1; a domain name that resolves to 127.0.0.1 (e.g., spoofed.burpcollaborator.net); URL encoding or case variation; and a controlled URL that redirects to the target URL, with different redirect codes and protocols. For whitelist-based filters, parser inconsistencies can be leveraged via the @ credential-embedding syntax (https://expected-host:fakepassword@evil-host), the # fragment (https://evil-host#expected-host), the DNS naming hierarchy (https://expected-host.evil-host), and double URL encoding.

*Disproof:* A claim that a correctly implemented whitelist makes SSRF impossible is refuted by PortSwigger's whitelist section, which demonstrates that ad-hoc validation using URL-parser inconsistencies (credentials, fragments, FQDN hierarchy, double-encoding) still leads to bypasses even when the filter matches at the beginning or within the input.

**An SSRF filter that resolves the hostname and checks the IP once, before connecting, is defeated by DNS rebinding, because the address the client connects to is resolved again and may differ.**

The Private Network Access explainer states the design requirement in the negative form: the mitigation operates upon the IP address which the user agent actually connects to when loading a particular resource, and this check MUST be performed for each new connection made, as DNS rebinding attacks may otherwise trick the user agent into revealing information it shouldn't. That 'for each new connection' is the whole bypass. A server-side analogue is a filter that validates the resolved address at request time and then performs a separate connect by hostname, giving the attacker two resolutions to win - a public address for the check and a private address for the connection, with a TTL low enough that the second answer differs. The hunter's technique is a low-TTL record alternating between a public address and 127.0.0.1 or a link-local address, and the pass condition is a callback or a response that only a private service could have produced.

*Disproof:* The claim is false when the filter pins the address: a client that connects to the validated IP with a Host header set separately, or one that resolves once and hands the socket to the request, has no second resolution to attack, and the check and the connection agree by construction. It also fails where the environment re-resolves or re-validates on every connection at a layer below the application - a proxy or egress gateway that performs its own resolution and address-space check, which is the architecture the Private Network Access document is describing on the browser side. And the attack requires an attacker-controlled DNS name that alternates, which many managed environments defeat by resolving once per process or by refusing low-TTL answers from untrusted resolvers.

**Where a request parameter takes an arbitrary URL, feeding it a loopback admin address and observing the server act on the fetched content is the test that turns that parameter into an SSRF sink and the entry point for escalation to code execution.**

Where a request parameter takes an arbitrary URL, feeding it a loopback admin address and observing the server act on the fetched content is the test that turns that parameter into an SSRF sink and the entry point for escalation to code execution.

HackTricks reference: AEM - Adobe Experience Cloud (network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md)

*Disproof:* Refuted when the loopback address in that parameter is rejected outright with the same error as a malformed value and no server-side fetch of the internal address ever occurs.

**Clearing one read-only callback handler does not clear the SSRF surface, because other registered backends in the same registry may still accept writes, so every registered handler has to be exercised before the feature is called safe.**

Clearing one read-only callback handler does not clear the SSRF surface, because other registered backends in the same registry may still accept writes, so every registered handler has to be exercised before the feature is called safe.

HackTricks reference: SSRF (Server Side Request Forgery) (pentesting-web/ssrf-server-side-request-forgery/README.md)

*Disproof:* Refuted if enumerating the registry returns only read-only handlers and no create/write entry point exists anywhere in the callback registration.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ssrf-to-cloud-metadata-credential-theft` — ssrf-to-cloud-metadata-credential-theft (goal: `cloud_credential_theft`)

## Real-World Examples

Not yet researched.

## Common False Positives

**An SSRF filter that restricts the scheme on the initial URL is not a control on the transfer if the client follows redirects, because the protocol allow-list applies to the follow-up request and is a separate setting from the initial one.**

libcurl makes the two-control distinction explicit in its API. CURLOPT_PROTOCOLS_STR takes a comma-separated list of case-insensitive protocol names and limits which protocols may be used in the transfer; by default libcurl accepts all protocols it was built with support for. CURLOPT_REDIR_PROTOCOLS_STR exists separately because that list limits what protocols may be used in a transfer that it follows to in a redirect when CURLOPT_FOLLOWLOCATION is enabled, and by default libcurl allows HTTP, HTTPS, FTP and FTPS on redirects. So an application that carefully sets CURLOPT_PROTOCOLS_STR to http,https and enables redirect-following has expressed two different intentions, and the second one is a default that permits four schemes. The field test is to send your own 302 to a scheme the initial filter forbids and see whether the client reaches it - that distinguishes an SSRF filter that covers the transfer from one that only covers the string it was handed.

*Disproof:* The claim is false when CURLOPT_REDIR_PROTOCOLS_STR is set to match the initial list, since the documentation is explicit that protocols denied by CURLOPT_PROTOCOLS_STR are not overridden by it, so a correctly configured pair holds for both the first request and every redirect. It is also false where the client does not follow redirects at all, or follows them with the scheme re-validated against the same allow-list by application code on each hop. And in runtimes other than libcurl the equivalent controls differ - Go's http.Client delegates redirect policy to a CheckRedirect hook that the caller must supply, so the gap here is specific to clients whose redirect scheme policy has a permissive default.

**A payload that a URL parser accepts with the host you intended does not prove the component that performs the fetch will use that host, because parsing and fetching are separate steps and are frequently performed by different code.**

The corpus already carries identify_which_component_parsed as a validation rule; this is its sharpest form. Go's net/url documents that trying to parse a hostname and path without a scheme is invalid but may not necessarily return an error, due to parsing ambiguities - so a payload that produces a parse error is not thereby blocked, and one that produces no error is not thereby going to be fetched as you read it. The split matters because validators typically run on a parsed structure while the fetch is performed by a client, a proxy, a resolver, or a shell-out, and each of those may re-derive the host, re-resolve it, apply its own redirect policy, or interpret a scheme the validator never modelled. The field rule is that the convincing evidence names the component: the fetch is proven by a callback or a response, and the parser disagreement is proven by the validator accepting a value the fetcher then sends somewhere else.

*Disproof:* The claim is false when the same component performs both the parse and the fetch and there is no intervening layer - a single library that validates the parsed URL and then dials the same URL object has no differential by construction, and a payload that appears in the outbound request at the intended host is the end of the question. It also fails when the evidence is an actual callback from a server only the attacker controls: that proves the fetch happened, whatever the validator thought. And a parser that rejects the payload outright with an error the application propagates is a genuine block, which is the case the rule is warning you not to mistake for one.

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
**Hypothesis:** The client bundle references URL-accepting parameters for import, webhook and avatar features, therefore the application is vulnerable to SSRF
- Invalidated by: The consuming endpoints require an authenticated session. Unauthenticated the parameter was ignored entirely - application shell or 404, no server-side fetch. No outbound request occurred
- **Rejection rule:** A URL parameter proves SSRF only when the SERVER acts on it. Probe it unauthenticated and look for a DNS or HTTP effect attributable to your input; an ignored parameter is not SSRF, and a feature that exists only behind a session you cannot obtain is untested rather than vulnerable

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

**OWASP's SSRF prevention guidance mandates allowlist-first validation, with a canonical deny-list of loopback, RFC1918 private, link-local, multicast, AWS/GCP/Azure metadata, and IPv6 unique-local ranges; it also warns that domain allowlisting alone does not stop DNS rebinding.**

The OWASP Server-Side Request Forgery Prevention Cheat Sheet states "Deny-lists are bypass-prone. Prefer allow-lists." Where a deny-list is unavoidable, it specifies blocks for AWS IMDS (169.254.169.254, metadata.amazonaws.com), GCP metadata (metadata.google.internal, 169.254.169.254), Azure IMDS (169.254.169.254), localhost (127.0.0.0/8, 0.0.0.0/8, ::1/128), RFC1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv6 unique local (fc00::/7), IPv6 link-local (fe80::/10), and multicast. For IP validation, the cheat sheet directs using battle-tested libraries (Apache Commons InetAddressValidator, .NET IPAddress.TryParse, ip-address, Ruby IPAddr) and comparing the library's output value against the allowlist; for domains it warns that domain allowlisting alone does not prevent DNS rebinding and requires connection-time enforcement after validation.

*Disproof:* A claim that validating a domain against an allowlist is sufficient because the resolved IP is checked before connecting is refuted by OWASP's own statement: "Domain allowlisting alone does not prevent DNS rebinding" and the instruction to validate the resolved destination IP against permitted networks and ensure the HTTP client connects only to validated addresses, with the warning that a second unchecked DNS lookup between validation and connection can bypass these checks.

**A filter that rejects a named set of internal addresses is weaker than an address-space check, because every address belongs to one of three spaces and the classification is defined by what the address means rather than by its literal value.**

The Private Network Access framework defines the classification that a real filter needs: every IP address belongs to an IP address space which can be one of three values - local, containing the local host only, so addresses whose target differs for every device; private, containing addresses that have meaning only within the current network, so addresses whose target differs based on network position; and public, containing all other addresses, whose target is the same for all devices globally. The value of this framing for a hunter is that it turns an unbounded deny-list into a closed test. Loopback, link-local, RFC1918, unique-local, carrier-grade NAT, and the cloud metadata address are instances, not the category - so a blocklist that misses one of them, or that misses a range in a network the target is deployed into, is incomplete in a way a space check is not. Testing should therefore cover at least one address from each space, and the report should state which space the target fell into.

*Disproof:* The claim does not mean a blocklist cannot be sufficient: in a deployment with a small, known internal surface, a deny-list covering every internal range plus a default-deny egress rule at the network layer is a real control, and the browser-side proposal itself is candid that it merely mitigates attacks against private web services and cannot fully solve them. It also fails as a claim of a specific finding if the untested range is not in the target's address plan - a 10.0.0.0/8 that the environment has no reason to use. The disproof has to come from an address that actually resolves and connects to something, not from a range in a table.

**A DNS lookup with no follow-up HTTP request indicates the request was blocked by network filtering, not that the SSRF is a false positive.**

When you see resolution of your unique domain but zero inbound HTTP, confirm the egress path rather than dismissing the finding. Re-test with an alternate destination and compare: if other external hosts also fail, the app is egress-restricted and the bug is present but unexploitable from that network. Record it as 'confirmed request initiation, filtered egress' so remediation targets both the SSRF and the network policy.

*Disproof:* If inbound HTTP requests to the same unique domain do arrive under identical egress conditions, the failure was transient and the DNS-only pattern is not explained by filtering.

**A bypass is only proven when the component that actually performs the fetch resolved a different host than the validating component approved.**

For each candidate bypass, reconstruct the fetch: which library or client made the request, which normalization step it applied, and which host it connected to. Compare that against what the filter inspected. A payload rejected by a strict allowlist comparison is not a bypass even if a client would have parsed it differently. Prefer evidence from the fetcher's own resolution (observed connection, response, timing) over reasoning about the regex.

*Disproof:* If the fetch connects to the allowlisted host for every variant, the allowlist held and no bypass occurred.

**To decide this case, observe: A payload rejected by a strict allowlist comparison is not a bypass even if a client would have parsed it differently.**

Derived from ssrf.validation.identify_which_component_parsed, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.validation.identify_which_component_parsed) states the full boundary.

**To decide this case, observe: Without a readable response you cannot show what was retrieved, so keep the finding scoped to 'server makes attacker-directed requests' and state the unproven parts explicitly.**

Derived from ssrf.fp_rule.oast_callback_is_not_exfil, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.oast_callback_is_not_exfil) states the full boundary.

**To decide this case, observe: A 4xx, a validation error, or a silent drop with no collaborator traffic is the expected outcome of working filtering.**

Derived from ssrf.fp_rule.rejected_payload_without_egress, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.rejected_payload_without_egress) states the full boundary.

## Impact

**The severity of a server-side request forgery finding comes from the network position and trust the application lends the forged request, not from the request existing at all, so a hunter must show what the server-side fetch reaches that the client origin cannot.**

The severity of a server-side request forgery finding comes from the network position and trust the application lends the forged request, not from the request existing at all, so a hunter must show what the server-side fetch reaches that the client origin cannot.

HackTricks reference: request forgery csrf and ssrf (https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf.md)

*Disproof:* If the server-side fetch is shown to originate from the attacker's own network position, or to reach nothing the client origin could not already reach itself, the leverage-based impact claim fails.

**Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.**

Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

*Disproof:* If the destination is restricted to an allowlist of external hosts and the response is never returned, none of those internal targets are reachable from the endpoint.

**Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.**

Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

*Disproof:* If the reachable functionality only issues read-only requests and cannot alter state on the internal service, the impact stops at reading.

**A server-side request that reaches the metadata endpoint yields tokens minted for the VM's managed identity, so the impact of that SSRF is credential takeover of every identity attached to the VM rather than plain information disclosure.**

A server-side request that reaches the metadata endpoint yields tokens minted for the VM's managed identity, so the impact of that SSRF is credential takeover of every identity attached to the VM rather than plain information disclosure.

HackTricks reference: Cloud SSRF (pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md)

*Disproof:* Refuted if the metadata request from the SSRF sink returns no token, or hands back a token naming an identity that is not attached to the target VM and is rejected when used.

**Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.**

Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

*Disproof:* If the destination is restricted to an allowlist of external hosts and the response is never returned, none of those internal targets are reachable from the endpoint.

**Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.**

Server-side fetch functionality abused through SSRF can be used to update internal resources as well as read them, so a report limited to information disclosure understates the reachable capability.

HackTricks reference: ssrf (https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md)

*Disproof:* If the reachable functionality only issues read-only requests and cannot alter state on the internal service, the impact stops at reading.

**SSRF is also an attribution and abuse-laundering primitive: requests appear to originate from the victim organization.**

Frame impact around what the server can reach on the attacker's behalf: spoofed source IP toward third parties, internal-only protocols and ports, and possible command execution in some configurations. Any request your server makes toward a host you do not own is a third-party interaction you cannot clean up, so prove impact against hosts you control or the target's own internal range, and stop before spraying third-party infrastructure.

*Disproof:* If the server is strictly limited to a small allowlisted set of first-party hosts with redirects disabled, onward third-party abuse and attribution laundering are not reachable.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (primary)
  - <https://attack.mitre.org/campaigns/C0029/>
  - <https://attack.mitre.org/techniques/T1190/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **ctid.mitre.org** (primary)
  - <https://ctid.mitre.org/mappings/attack/attack-16.1/domain-enterprise/techniques/T1190/>
- **curl.se** (writeup)
  - <https://curl.se/libcurl/c/CURLOPT_PROTOCOLS_STR.html>
- **cwe.mitre.org** (research)
  - <https://cwe.mitre.org/data/definitions/441.html>
  - <https://cwe.mitre.org/data/definitions/918.html>
- **datatracker.ietf.org** (standard)
  - <https://datatracker.ietf.org/doc/html/rfc9110>
- **docs.aws.amazon.com** (writeup)
  - <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>
- **feed.craftedsignal.io** (writeup)
  - <https://feed.craftedsignal.io/briefs/2026-07-web-server-cloud-metadata-ssrf/>
- **go.dev** (writeup)
  - <https://go.dev/src/net/url/url.go>
- **httpd.apache.org** (writeup)
  - <https://httpd.apache.org/docs/2.4/mod/mod_proxy.html>
- **ietf.org** (standards_body)
  - <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
  - <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
- **oreobiscuit.gitbook.io** (reference)
  - <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf.md>
- **owasp.org** (research)
  - <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/>
  - <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>
- **pkg.go.dev** (writeup)
  - <https://pkg.go.dev/net/http>
- **portswigger.net** (research_doc)
  - <https://portswigger.net/web-security/ssrf>
  - <https://portswigger.net/web-security/ssrf/blind>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
  - <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/oouch-write-up.md>
  - <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/travel-write-up.md>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc3986.html>
  - <https://www.rfc-editor.org/rfc/rfc5737.txt>
- **unit42.paloaltonetworks.com** (advisory)
  - <https://unit42.paloaltonetworks.com/threat-brief-owassrf/>
- **wicg.github.io** (writeup)
  - <https://wicg.github.io/private-network-access/>
- **wiz.io** (research)
  - <https://www.wiz.io/blog/red-agent-pov-ssrf>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
