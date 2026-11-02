# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 00:09 — 1 diff lines
- items: 11 (supported 11), FP rules 0, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 01:36 — 11 diff lines
- items: 11 (supported 11), FP rules 0, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- ssrf@current
+++ ssrf@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
 > evidence: 11 items, 11 supported, 0 FP rules, 0 chains
```

## 2026-10-02 10:30 — 111 diff lines
- items: 14 (supported 11), FP rules 14, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
-> evidence: 11 items, 11 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, fp_rules, chain
+> evidence: 14 items, 11 supported, 14 FP rules, 1 chains
+> maturity: **mature**
 
 The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.
 
@@ -32,15 +32,15 @@
 
 ## Techniques (what to change)
 
-- Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target.
+- Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target. _(unverified)_
   - **Disproof:** If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>
+  - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
 - SSRF impact is highest when the server is trusted by its own front-end controls, bypassing access control on loopback or private back-ends.
   - **Disproof:** If loopback and private-range requests are refused at the network layer with no connection at all, the trust-escalation path is unavailable in this deployment.
   - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://portswigger.net/web-security/ssrf>
 - Allowlist validators and the back-end HTTP client parse URLs differently, so a URL the validator accepts can still resolve elsewhere.
   - **Disproof:** If every one of these variants is rejected identically by both validator and fetcher, no parser differential exists on this endpoint.
-  - Sources: <https://portswigger.net/web-security/ssrf> · <https://www.rfc-editor.org/rfc/rfc3986.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://portswigger.net/web-security/ssrf>
 
 ## Validation bar (how to prove it)
 
@@ -49,7 +49,7 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf/blind>
 - A bypass is only proven when the component that actually performs the fetch resolved a different host than the validating component approved.
   - **Disproof:** If the fetch connects to the allowlisted host for every variant, the allowlist held and no bypass occurred.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc3986.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc3986.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
@@ -59,6 +59,12 @@
 - A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.
   - **Disproof:** If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/ssrf>
+- A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix. _(unverified)_
+  - **Disproof:** If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html>
+- Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside. _(unverified)_
+  - **Disproof:** If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc9110> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html>
 
 ## Impact framing
 
@@ -68,9 +74,55 @@
 
 ## Chaining opportunities
 
+- An SSRF that the application's own filters do not recognise as reaching a metadata endpoint still yields instance credentials, which are then spent with the ambient authority of the hosting application identity rather than the anonymous attacker.
+  - **Disproof:** Refuted when the metadata service requires an identity-bound header such as an instance identity document or when the workload runs with no attached service account; the fetch then returns nothing an attacker can redeem.
+  - Sources: <https://unit42.paloaltonetworks.com/threat-brief-owassrf/> · <https://www.wiz.io/blog/red-agent-pov-ssrf>
 - An SSRF whose scheme is attacker-chained into file://, gopher://, or dict:// upgrades a read-only web fetch into local file access or arbitrary-protocol byte delivery.
   - **Disproof:** If the fetcher rejects every non-HTTP scheme with an error and never dereferences them, the scheme-abuse chain is unavailable.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/918.html>
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
+
+## Rejected before you report
+
+- **The image-fetch endpoint is vulnerable to SSRF because it returns HTTP 200 for an internal URL**
+  - Killed by: An unresolvable domain and a malformed URL also returned HTTP 200 with the same non-empty placeholder body, so the 200 is the endpoint accepting the parameter, not a successful outbound fetch
+  - Rule: A fetch endpoint that returns 200 for unresolvable and malformed URLs is not proving SSRF; the body must contain content that could only come from the target you supplied
+- **A hostname allowlist is bypassed because a public hostname resolving to an internal address was fetched**
+  - Killed by: The hostname resolved publicly from the attacker's network but to a private address from inside the organisation's split-horizon DNS, so the internal content came from the target's own resolver, not from a bypass
+  - Rule: Internal content behind a public hostname may be split-horizon DNS rather than a filter bypass; resolve the name from both networks before attributing it to validation logic
+- **The server follows redirects, so an allowed host redirecting to a blocked internal address proves SSRF**
+  - Killed by: The internal content was returned in the CLIENT's response to the attacker, not in the server's fetch result, so the server returned the redirect and stopped - it did not follow it
+  - Rule: Redirect-based SSRF requires the internal content in the SERVER's fetch result; a 302 handed back to your own client is the server refusing to follow, not a bypass
+- **The endpoint is blind SSRF because a slow internal host produces a measurable delay**
+  - Killed by: The delay was present on the public-URL baselines too and matched the delay of a deliberately slow public host, so timing reflects the outbound network, not a reachable internal service
+  - Rule: A blind SSRF claim from timing needs the delay to track the payload across many samples; a uniformly slow network produces the same symptom with no vulnerability
+- **A file:// scheme in the URL parameter reads local files, proving SSRF**
+  - Killed by: The endpoint's purpose is avatar upload and file storage, so a file scheme is a local file inclusion issue against a different trust boundary, not a request forgery
+  - Rule: A file:// read is LFI, not SSRF; classify the primitive before reporting, because the two have different root causes, owners and fixes
+- **The URL is fetched by the server because the resulting image renders in the page**
+  - Killed by: The URL was returned as a plain img src attribute in the HTML and the browser performed the retrieval, so nothing server-side was involved
+  - Rule: A URL in an img src is a client-side fetch by definition; SSRF requires evidence the SERVER retrieved it, not that a browser did
+- **The webhook endpoint is exploitable because it delivers a POST to an attacker-controlled URL**
+  - Killed by: The webhook destination must be configured by an authenticated administrator, the delivered payload contained only non-sensitive event metadata, and no internal network was reachable through it
+  - Rule: A webhook is not SSRF when only an authenticated owner can set the destination and the delivered data is non-sensitive; the capability is the feature
+- **The URL is validated against an allowlist but internal hosts are reachable through DNS rebinding**
+  - Killed by: The response came from the ATTACKER's own loopback service, which is reachable from the attacker's machine anyway, so nothing internal to the target was disclosed
+  - Rule: A rebind that resolves to the attacker's own loopback proves nothing; the rebound address must be inside the victim network for impact to exist
+- **A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.**
+  - Killed by: If you can also read internal response content or observe internal state change, the blind callback was an incomplete description of a proven data-access SSRF.
+  - Rule: A confirmed blind SSRF callback proves request initiation only; it is not by itself evidence of internal data read or exfiltration.
+- **A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.**
+  - Killed by: If a blocked-value request still produces a server-originated connection or internal response, the filter did not prevent the request and a bypass exists.
+  - Rule: A payload that a blocklist rejects and which produces no outbound connection is a failed attempt, not a filter bypass.
+- **A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.**
+  - Killed by: If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.
+  - Rule: A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.
+- **Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.**
+  - Killed by: If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.
+  - Rule: Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.
+
+## Chains to
+
+- `api_trust` (3 shared chain(s))
 
 ---
 Full class document: `classes/ssrf.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssrf`
```

## 2026-10-02 13:38 — 33 diff lines
- items: 17 (supported 14), FP rules 14, chains 1, state mature

```diff
--- ssrf@current
+++ ssrf@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-918 · OWASP A10:2021
-> evidence: 14 items, 11 supported, 14 FP rules, 1 chains
+> evidence: 17 items, 14 supported, 14 FP rules, 1 chains
 > maturity: **mature**
 
 The server fetches a URL influenced by the attacker, crossing a trust boundary into networks the attacker cannot reach directly.
@@ -32,6 +32,15 @@
 
 ## Techniques (what to change)
 
+- The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly".
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
+- SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SSRF in LLM application development framework because the URL retriever allows connections".
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
+- Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enables parsing of octal or hexadecimal formats ( CWE-1389 ), allowing bypass of an SSRF protection mechanism ( CWE-918 ).
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: incorrect validation of intended decimal-based IP address format ( CWE-1286 ) enabl".
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://portswigger.net/web-security/ssrf>
 - Cloud instance metadata services are reachable at 169.254.169.254 and by vendor DNS name, unauthenticated by default, making them the primary SSRF target. _(unverified)_
   - **Disproof:** If the metadata IP and DNS name both fail to connect or the metadata service rejects unauthenticated GETs, there is no metadata exposure via SSRF.
   - Sources: <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
@@ -125,4 +134,4 @@
 - `api_trust` (3 shared chain(s))
 
 ---
-Full class document: `classes/ssrf.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssrf`
+Full class document: `skills/Web/ssrf/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssrf`
```
