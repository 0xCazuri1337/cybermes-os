# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 17 (supported 17), FP rules 16, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 17 (supported 17), FP rules 16, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -134,4 +134,4 @@
 - `api_trust` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/ssrf/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssrf`
+Full class document: `domains/web/ssrf/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssrf`
```

## 2026-10-02 19:37 — 47 diff lines
- items: 20 (supported 17), FP rules 16, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
-> evidence: 17 items, 17 supported, 16 FP rules, 1 chains
+> evidence: 20 items, 17 supported, 16 FP rules, 1 chains
 > maturity: **mature**
 
 The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.
@@ -32,13 +32,13 @@
 
 ## Techniques (what to change)
 
-- The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.
+- The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
-- SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header
+- SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
-- Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ).
+- Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
 - Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.
@@ -50,6 +50,18 @@
 - Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.
   - **Disproof:** If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
   - Sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://portswigger.net/web-security/ssrf>
+
+## Tests
+
+- To decide this case, observe: ent would have parsed it differently. Prefer evidence from the fetcher's own resolution (observed connection, response, timing) over reasoning about the regex.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.validation.identify_which_component_parsed) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
+- To decide this case, observe: er makes attacker-directed requests' and state the unproven parts explicitly. Escalate only with additional evidence: a reflected internal response, a distinguishable internal state change, or a second-stage result observed out of band. Otherwise the finding is real but its impact ceiling is unknown.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.oast_callback_is_not_exfil) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
+- To decide this case, observe: tion error, or a silent drop with no collaborator traffic is the expected outcome of working filtering. Report bypasses only when a connection to the blocked resource is demonstrated, and pair every candidate bypass with a baseline request that the filter legitimately refuses.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.rejected_payload_without_egress) states the full boundary.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 177 diff lines
- items: 49 (supported 41), FP rules 18, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
-> evidence: 20 items, 17 supported, 16 FP rules, 1 chains
+> evidence: 49 items, 41 supported, 18 FP rules, 1 chains
 > maturity: **mature**
 
 The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.
@@ -20,12 +20,30 @@
 
 ## Prerequisites (do not start without these)
 
+- A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.
+  - **Disproof:** Refuted if a registered callback value is never fetched by the server - it only appears in outbound mail or client-side rendering, or registration is pinned to a fixed allowlisted host.
+  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
 - Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.
   - **Disproof:** If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>
 
 ## Recon signals (where to look)
 
+- An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead. _(unverified)_
+  - **Disproof:** A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
+- Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.
+  - **Disproof:** Refuted if the same error class is returned for an empty or syntactically invalid URL that can never produce an outbound request, meaning the errors track input validation rather than a request leaving the host.
+  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
+- A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated. _(unverified)_
+  - **Disproof:** A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
+- An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.
+  - **Disproof:** A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
+- A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.
+  - **Disproof:** A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
 - A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.
   - **Disproof:** If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
@@ -41,9 +59,33 @@
 - Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
+- A server-side request forgery is confirmed when a URL supplied by the client is fetched by the server and its response body is reflected back to the client.
+  - **Disproof:** Refuted when the server performs the fetch but returns no attacker-observable signal (status, timing, or body difference), in which case no request forgery is provable.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/oouch-write-up.md>
 - Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.
   - **Disproof:** If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
+- Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.
+  - **Disproof:** Refuted if the final artifact is byte-identical whether the callback URL is tester-controlled or replaced with an unreachable one, or the fetched body is never stored or re-rendered anywhere visible.
+  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
+- When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.
+  - **Disproof:** Refuted if requesting a token from the metadata endpoint without naming an identity succeeds and returns a token for the intended user-assigned identity, or if the platform configuration endpoint lists no identities at all.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md>
+- Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.
+  - **Disproof:** Refuted if a filename containing encoded newlines adds no headers to the outbound request because the request line is percent-encoded, or if the metadata endpoint answers identically regardless of the injected headers.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
+- The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for. _(unverified)_
+  - **Disproof:** If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
+- A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.
+  - **Disproof:** Refuted if changing the SNI value does not change the host the server connects to - behaviour is identical for an attacker SNI, a bogus SNI and no SNI at all.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
+- Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.
+  - **Disproof:** Refuted when the automated sweep reports no SSRF yet a manual request to the same bypassed URL with an attacker-controlled host does produce an outbound callback, which shows the tool missed a live sink.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md>
+- The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.
+  - **Disproof:** If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
 - SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.
   - **Disproof:** If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
   - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://portswigger.net/web-security/ssrf>
@@ -53,18 +95,21 @@
 
 ## Tests
 
-- To decide this case, observe: ent would have parsed it differently. Prefer evidence from the fetcher's own resolution (observed connection, response, timing) over reasoning about the regex.
+- To decide this case, observe: A payload rejected by a strict allowlist comparison is not a bypass even if a client would have parsed it differently.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.validation.identify_which_component_parsed) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
-- To decide this case, observe: er makes attacker-directed requests' and state the unproven parts explicitly. Escalate only with additional evidence: a reflected internal response, a distinguishable internal state change, or a second-stage result observed out of band. Otherwise the finding is real but its impact ceiling is unknown.
+- To decide this case, observe: Without a readable response you cannot show what was retrieved, so keep the finding scoped to 'server makes attacker-directed requests' and state the unproven parts explicitly.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.oast_callback_is_not_exfil) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
-- To decide this case, observe: tion error, or a silent drop with no collaborator traffic is the expected outcome of working filtering. Report bypasses only when a connection to the blocked resource is demonstrated, and pair every candidate bypass with a baseline request that the filter legitimately refuses.
+- To decide this case, observe: A 4xx, a validation error, or a silent drop with no collaborator traffic is the expected outcome of working filtering.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssrf.fp_rule.rejected_payload_without_egress) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf>
 
 ## Validation bar (how to prove it)
 
+- A filter that rejects a named set of internal addresses is weaker than an address-space check, because every address belongs to one of three spaces and the classification is defined by what the address means rather than by its literal value.
+  - **Disproof:** The claim does not mean a blocklist cannot be sufficient: in a deployment with a small, known internal surface, a deny-list covering every internal range plus a default-deny egress rule at the network layer is a real control, and the browser-side proposal itself is candid that it merely mitigates attacks against private web services and cannot fully solve them. It also fails as a claim of a specific finding if the untested range is not in the target's address plan - a 10.0.0.0/8 that the environment has no reason to use. The disproof has to come from an address that actually resolves and connects to something, not from a range in a table.
+  - Sources: <https://pkg.go.dev/net/http> · <https://wicg.github.io/private-network-access/>
 - A DNS lookup with no follow-up HTTP request indicates the request was blocked by network filtering, not that the SSRF is a false positive.
   - **Disproof:** If inbound HTTP requests to the same unique domain do arrive under identical egress conditions, the failure was transient and the DNS-only pattern is not explained by filtering.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>
@@ -74,6 +119,12 @@
 
 ## False-positive rules (when to reject it)
 
+- An SSRF filter that restricts the scheme on the initial URL is not a control on the transfer if the client follows redirects, because the protocol allow-list applies to the follow-up request and is a separate setting from the initial one.
+  - **Disproof:** The claim is false when CURLOPT_REDIR_PROTOCOLS_STR is set to match the initial list, since the documentation is explicit that protocols denied by CURLOPT_PROTOCOLS_STR are not overridden by it, so a correctly configured pair holds for both the first request and every redirect. It is also false where the client does not follow redirects at all, or follows them with the scheme re-validated against the same allow-list by application code on each hop. And in runtimes other than libcurl the equivalent controls differ - Go's http.Client delegates redirect policy to a CheckRedirect hook that the caller must supply, so the gap here is specific to clients whose redirect scheme policy has a permissive default.
+  - Sources: <https://curl.se/libcurl/c/CURLOPT_PROTOCOLS_STR.html> · <https://pkg.go.dev/net/http>
+- A payload that a URL parser accepts with the host you intended does not prove the component that performs the fetch will use that host, because parsing and fetching are separate steps and are frequently performed by different code.
+  - **Disproof:** The claim is false when the same component performs both the parse and the fetch and there is no intervening layer - a single library that validates the parsed URL and then dials the same URL object has no differential by construction, and a payload that appears in the outbound request at the intended host is the end of the question. It also fails when the evidence is an actual callback from a server only the attacker controls: that proves the fetch happened, whatever the validator thought. And a parser that rejects the payload outright with an error the application propagates is a genuine block, which is the case the rule is warning you not to mistake for one.
+  - Sources: <https://go.dev/src/net/url/url.go> · <https://wicg.github.io/private-network-access/>
 - A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.
   - **Disproof:** If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
@@ -82,16 +133,61 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf>
 - A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.
   - **Disproof:** If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
-  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/ssrf>
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://datatracker.ietf.org/doc/html/rfc9110> · <https://portswigger.net/web-security/ssrf>
... (truncated)
```

## 2026-10-03 02:41 — 21 diff lines
- items: 50 (supported 42), FP rules 18, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
-> evidence: 49 items, 41 supported, 18 FP rules, 1 chains
+> evidence: 50 items, 42 supported, 18 FP rules, 1 chains
 > maturity: **mature**
 
 The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.
@@ -155,6 +155,9 @@
 
 ## Impact framing
 
+- The severity of a server-side request forgery finding comes from the network position and trust the application lends the forged request, not from the request existing at all, so a hunter must show what the server-side fetch reaches that the client origin cannot.
+  - **Disproof:** If the server-side fetch is shown to originate from the attacker's own network position, or to reach nothing the client origin could not already reach itself, the leverage-based impact claim fails.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf.md>
 - Choice of URL is the exploitation lever once the fetch is reachable: the same server-side request can be aimed at cloud metadata, an internal HTTP-enabled database, or an internal service via POST, so what matters is whether the destination and the request method are attacker-selectable. _(unverified)_
   - **Disproof:** If the destination is restricted to an allowlist of external hosts and the response is never returned, none of those internal targets are reachable from the endpoint.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
```

## 2026-10-03 05:00 — 21 diff lines
- items: 50 (supported 42), FP rules 19, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
-> evidence: 50 items, 42 supported, 18 FP rules, 1 chains
+> evidence: 50 items, 42 supported, 19 FP rules, 1 chains
 > maturity: **mature**
 
 The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.
@@ -239,6 +239,9 @@
 - **Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.**
   - Killed by: If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
   - Rule: Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.
+- **The client bundle references URL-accepting parameters for import, webhook and avatar features, therefore the application is vulnerable to SSRF**
+  - Killed by: The consuming endpoints require an authenticated session. Unauthenticated the parameter was ignored entirely - application shell or 404, no server-side fetch. No outbound request occurred
+  - Rule: A URL parameter proves SSRF only when the SERVER acts on it. Probe it unauthenticated and look for a DNS or HTTP effect attributable to your input; an ignored parameter is not SSRF, and a feature that exists only behind a session you cannot obtain is untested rather than vulnerable
 
 ## Chains to
 
```

## 2026-10-04 00:43 — 306 diff lines
- items: 50 (supported 42), FP rules 19, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -20,184 +20,169 @@
 
 ## Prerequisites (do not start without these)
 
-- A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.
+- A user-registrable callback URL is the precondition that turns any later server-side fetch into an SSRF pivot, so callback and webhook registration fields are the first surface to inventory for blind SSRF.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a registered callback value is never fetched by the server - it only appears in outbound mail or client-side rendering, or registration is pinned to a fixed allowlisted host.
   - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
-- Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.
+- Exploitability of any SSRF is bounded by the vulnerable server's outbound egress: DNS, HTTP, and allowed destinations.  _(merged 1 duplicate row(s))_
   - **Disproof:** If even DNS resolution of your unique domain never occurs, the parameter never triggers a server-side lookup and the SSRF hypothesis is wrong.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>
 
 ## Recon signals (where to look)
 
-- An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead. _(unverified)_
+- A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
+- A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
+- An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
-  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
-- Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.
+  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
+- Errors that depart from the baseline of a well-formed URL - DNS failure, TLS validation error, 401 from a metadata service, scheme-parsing error - are usable as positive proof that a server-side outbound request was issued and reached internal-only destinations.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the same error class is returned for an empty or syntactically invalid URL that can never produce an outbound request, meaning the errors track input validation rather than a request leaving the host.
   - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
-- A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated. _(unverified)_
-  - **Disproof:** A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
-  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
-- An SSRF whose response never returns the fetched content is blind, so the response body alone cannot confirm the server-side fetch and the finding has to rest on out-of-band evidence instead.
-  - **Disproof:** A response that returns the fetched content, or a repeatable distinguishable error or timing difference, shows the fetch is directly observable and the endpoint is not blind.
-  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
-- A referrer-analysing service on the target side records the Referer URL the browser sends, so a collaborator-domain URL appearing in a referrer log confirms that outbound traffic to a URL the attacker chose was generated.
-  - **Disproof:** A target that strips the Referer on navigation, or a collaborator log showing no hit from the target's address, provides no such confirmation.
-  - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/blind_ssrf.md>
-- A server-originated HTTP request to a unique domain you control is the definitive signal of blind SSRF.
-  - **Disproof:** If no unique token ever appears in inbound logs and no correlated DNS resolution occurs, the field did not trigger a server-side request.
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf/blind>
 
 ## Techniques (what to change)
 
-- The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
-- SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
-- Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
-- A server-side request forgery is confirmed when a URL supplied by the client is fetched by the server and its response body is reflected back to the client.
+- A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if changing the SNI value does not change the host the server connects to - behaviour is identical for an attacker SNI, a bogus SNI and no SNI at all.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
+- A server-side request forgery is confirmed when a URL supplied by the client is fetched by the server and its response body is reflected back to the client.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the server performs the fetch but returns no attacker-observable signal (status, timing, or body difference), in which case no request forgery is provable.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/oouch-write-up.md>
-- Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.
+- Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://portswigger.net/web-security/ssrf>
+- Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the final artifact is byte-identical whether the callback URL is tester-controlled or replaced with an unreachable one, or the fetched body is never stored or re-rendered anywhere visible.
+  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
+- Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ).  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
+- Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
-- Blind SSRF escalates to exfiltration without ever seeing the raw HTTP body by pointing the URL at a benign text endpoint and then looking for that fetched text reproduced inside the downstream artifact the tester can actually read.
-  - **Disproof:** Refuted if the final artifact is byte-identical whether the callback URL is tester-controlled or replaced with an unreachable one, or the fetched body is never stored or re-rendered anywhere visible.
-  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms.md>
-- When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.
+- Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the automated sweep reports no SSRF yet a manual request to the same bypassed URL with an attacker-controlled host does produce an outbound callback, which shows the tool missed a live sink.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md>
+- Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if a filename containing encoded newlines adds no headers to the outbound request because the request line is percent-encoded, or if the metadata endpoint answers identically regardless of the injected headers.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
+- SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
+  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://portswigger.net/web-security/ssrf>
+- SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
+- The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
+- The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
+- When a VM has several user-assigned managed identities and no system-assigned one, the metadata service errors out instead of issuing a token, so identity enumeration has to pivot to the platform configuration endpoint to learn which identities exist.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if requesting a token from the metadata endpoint without naming an identity succeeds and returns a token for the intended user-assigned identity, or if the platform configuration endpoint lists no identities at all.
   - Sources: <https://cwe.mitre.org/data/definitions/441.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md>
-- Newlines smuggled through a filename field can inject extra headers into the outbound request, which is how a cloud metadata service that demands specific headers is reached from a server-side request.
-  - **Disproof:** Refuted if a filename containing encoded newlines adds no headers to the outbound request because the request line is percent-encoded, or if the metadata endpoint answers identically regardless of the injected headers.
-  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
-- The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for. _(unverified)_
-  - **Disproof:** If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
-- A TLS ClientHello whose SNI carries the tester's target host steers the server-side connection, so a user-controlled SNI echoed verbatim from input is a probe for server-side request forgery.
-  - **Disproof:** Refuted if changing the SNI value does not change the host the server connects to - behaviour is identical for an attacker SNI, a bogus SNI and no SNI at all.
-  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssrf-server-side-request-forgery/README.md>
-- Enumerate the whole parameter surface with an automated sweep rather than by hand, because a single enumeration script bundles SSRF detection together with dispatcher-bypass attempts, making untrusted-origin reachability the first property to establish on the target.
-  - **Disproof:** Refuted when the automated sweep reports no SSRF yet a manual request to the same bypassed URL with an attacker-controlled host does produce an outbound callback, which shows the tool missed a live sink.
-  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.md>
-- The attacker action in an SSRF is supplying or modifying the URL that server-side code dereferences, which makes any parameter that changes the fetch destination the entry point to hunt for.
-  - **Disproof:** If the destination URL is fixed or restricted to a server-side allowlist such that user input cannot change the host fetched, there is no entry point.
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/> · <https://kathan19.gitbook.io/howtohunt/ssrf/ssrf.md>
-- SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.
-  - **Disproof:** If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
-  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://portswigger.net/web-security/ssrf>
-- Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.
... (truncated)
```

## 2026-10-04 00:50 — 16 diff lines
- items: 50 (supported 42), FP rules 19, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -235,10 +235,9 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Canary first: make the server fetch a collaborator domain (interactsh / oastify) to confirm outbound egress before probing internal hosts.
+2. Try the usual bypass ladder in order: @ in the userinfo, a # fragment, a decimal or hex IP, and a DNS name that resolves to 127.0.0.1.
+3. Read response headers and body for cloud metadata (169.254.169.254) and keep the raw response; the status code alone proves nothing.
 
 ### What counts as proof
 
```
