# Methodology — Server-Side Request Forgery

> Derived from 14 verified items. Regenerate with `python -m wks.methodgen --class ssrf --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.

**References.** CWE-918 · A10:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.**

Determine the app server's egress posture before rating impact. Infrastructure often permits outbound DNS while filtering outbound HTTP, so a blind SSRF may be real but reach only a resolver. If a network-layer restriction exists the finding is a defense-in-depth gap rather than a confirmed fetch. Record which of DNS resolution, TCP connect, and HTTP response actually occurred; these are three distinct proofs with three different severities.

- *Disproof:* If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.**

Generate a unique per-payload domain on a collaborator service, embed it in each candidate URL field (including nested JSON/XML values and secondary fetches), then monitor for DNS and HTTP interactions correlated to that exact token. Correlating a unique token per request avoids false positives from scanners and crawlers. Only an inbound HTTP request counts as proof; a DNS lookup alone is a weaker, separately-graded signal.

- *Disproof:* If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.**

Probe loopback aliases and private ranges from the app server: 127.0.0.1, localhost, alternative IP encodings of 127.0.0.1, RFC1918 targets, and alternate ports where an admin interface listens. High-value targets are components that treat a request originating locally as trusted, including management interfaces, DR-only unauthenticated admin paths, and sidecar APIs. Response differences (status, body length, timing) reveal reachability even when the body is filtered.

- *Disproof:* If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery); [portswigger.net](https://portswigger.net/web-security/ssrf)

**Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.**

Probe parser differentials: userinfo tricks such as https://expected-host:pass@evil-host, fragments such as https://evil-host#expected-host, suffix matching such as https://expected-host.evil-host, percent- and double-encoding, and case variation. Also test rare IP literal forms (dword, octal, hex, short forms) and IPv6 bracket literals. The host production is genuinely ambiguous, so implementations legitimately disagree; judge each payload on which component parsed it.

- *Disproof:* If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/ssrf); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc3986.html)

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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

**SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header**

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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

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

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.**

When a blacklist-style filter rejects 127.0.0.1, localhost, or a sensitive path, treat the rejection as a correct control unless you observe the server still connecting. A 4xx, a validation error, or a silent drop with no collaborator traffic is the expected outcome of working filtering. Report bypasses only when a connection to the blocked resource is demonstrated, and pair every candidate bypass with a baseline request that the filter legitimately refuses.

- *Disproof:* If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

**A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.**

Do not upgrade a blind SSRF on the strength of a collaborator hit alone. Without a readable response you cannot show what was retrieved, so keep the finding scoped to 'server makes attacker-directed requests' and state the unproven parts explicitly. Escalate only with additional evidence: a reflected internal response, a distinguishable internal state change, or a second-stage result observed out of band. Otherwise the finding is real but its impact ceiling is unknown.

- *Disproof:* If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf/blind)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An SSRF that the application's own filters do not recognise as reaching a metadata endpoint still yields instance credentials, which are then spent with the ambient authority of the hosting application identity rather than the anonymous attacker.**

The published Red Agent case is a worked example of the whole assembly: it uncovered a multi-step attack chain allowing ssrf-to-local-file-read on a GCP Cloud Run API, and it probed the url parameter with authority-confusion and fragment techniques precisely because the naive metadata request was validated. The generic statement of why SSRF escalates is that an attacker can abuse the server's trusted network position to force it into interacting with internal-only services, querying cloud metadata endpoints to extract credentials, or reading local files through alternative URI schemes. The second half of the chain is the credential's scope: application identities typically carry broad access, so the harvest is spent with the app's own authority. Vendor post-exploitation telemetry on a widely exploited server-side flaw confirms the destination half as well, with operators dumping LSASS memory to harvest credentials rather than acting locally.

- *Disproof:* Refuted when the metadata service requires an identity-bound header such as an instance identity document or when the workload runs with no attached service account; the fetch then returns nothing an attacker can redeem.
- *Evidence:* high_confidence — [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/threat-brief-owassrf/); [wiz.io](https://www.wiz.io/blog/red-agent-pov-ssrf)

**An SSRF whose scheme is attacker-chained into file://, gopher://, or dict:// upgrades a read-only web fetch into local file access or arbitrary-protocol byte delivery.**

Once request initiation is confirmed, determine whether the scheme is restricted to http/https. If the fetcher honors arbitrary schemes, chain from HTTP to file:// for local file read, and to gopher:// or dict:// for crafting arbitrary bytes toward internal services speaking line- or field-oriented plaintext protocols, which is how cache poisoning and CRLF injection against internal services are reached. Verify the scheme is rejected before claiming the chain.

- *Disproof:* If the fetcher rejects every non-HTTP scheme with an error and never dereferences them, the scheme-abuse chain is unavailable.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html)

## 7. Impact

_What is actually demonstrable, and what to stop claiming._

**SSRF is also an attribution and abuse-laundering primitive: requests appear to originate from the victim organization.**

Frame impact around what the server can reach on the attacker's behalf: spoofed source IP toward third parties, internal-only protocols and ports, and possible command execution in some configurations. Any request your server makes toward a host you do not own is a third-party interaction you cannot clean up, so prove impact against hosts you control or the target's own internal range, and stop before spraying third-party infrastructure.

- *Disproof:* If the server is strictly limited to a small allowlisted set of first-party hosts with redirects disabled, onward third-party abuse and attribution laundering are not reachable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [portswigger.net](https://portswigger.net/web-security/ssrf)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Known bypasses.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
