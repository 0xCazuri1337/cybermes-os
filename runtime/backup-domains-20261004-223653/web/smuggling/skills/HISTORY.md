# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 17 (supported 17), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 17 (supported 17), FP rules 2, chains 1, state mature

```diff
--- smuggling@current
+++ smuggling@new
@@ -79,4 +79,4 @@
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
 
 ---
-Full class document: `domains/web/smuggling/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smuggling`
+Full class document: `domains/web/smuggling/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smuggling`
```

## 2026-10-02 19:37 — 74 diff lines
- items: 17 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- smuggling@current
+++ smuggling@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 17 items, 17 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 17 items, 3 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: supported_items
 
 Front-end and back-end disagree about where one request ends, so one request becomes two.
 
@@ -26,46 +26,46 @@
 
 ## Techniques (what to change)
 
-- It basically enables you to hide a payload in plain sight.
+- It basically enables you to hide a payload in plain sight. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
   - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- It does not indicate successful exploitation on patched devices.
+- It does not indicate successful exploitation on patched devices. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- It does not indicate successful exploitation on patched devices.
+- It does not indicate successful exploitation on patched devices. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The grep -q guard prevents duplicate injection if the persistence mechanism is run again.
+- The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The grep -q guard prevents duplicate injection if the persistence mechanism is run again.
+- The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
   - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- It basically enables you to hide a payload in plain sight.
+- It basically enables you to hide a payload in plain sight. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
   - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.
+- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.
+- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.
+- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
   - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.
+- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.
+- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.
+- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
-- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.
+- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.
+- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 
```

## 2026-10-03 01:46 — 153 diff lines
- items: 34 (supported 18), FP rules 3, chains 1, state mature

```diff
--- smuggling@current
+++ smuggling@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 17 items, 3 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: supported_items
+> evidence: 34 items, 18 supported, 3 FP rules, 1 chains
+> maturity: **mature**
 
 Front-end and back-end disagree about where one request ends, so one request becomes two.
 
 **Also called:** request smuggling, http desync, cl te, te cl
 
+
+## Prerequisites (do not start without these)
+
+- Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.
+  - **Disproof:** Refuted if a desync is reproducible entirely within HTTP/2 with no downgrade involved, which would mean frame length is not enforced end to end.
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
 
 ## Recon signals (where to look)
 
@@ -28,10 +34,10 @@
 
 - It basically enables you to hide a payload in plain sight. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
-  - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - It does not indicate successful exploitation on patched devices. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - It does not indicate successful exploitation on patched devices. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
@@ -40,19 +46,19 @@
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
-  - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - It basically enables you to hide a payload in plain sight. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
-  - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
-  - Sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
@@ -61,22 +67,88 @@
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 - The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
+- The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.
+  - **Disproof:** Refuted if both hops resolve the same request boundary for the conflicting message, or if the front end strips the offending header before forwarding so the back end never sees the ambiguity.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/README.md>
+- The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.
+  - **Disproof:** Refuted if attacker-chosen Content-Length or Transfer-Encoding values survive verbatim into the downgraded request when observed downstream.
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
+- Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.
+  - **Disproof:** Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.
+  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
+- HTTP request smuggling arises where a front-end and back-end disagree on where a request ends, so a smuggled request is prepended to the next legitimate user's request.
+  - **Disproof:** Refuted when a front end rejects ambiguous framing outright, or when both hops agree on message boundaries for the same request, leaving no request to smuggle.
+  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/quick-write-up.md>
+
+## Tests
+
+- An invalid or duplicated Content-Length with no Transfer-Encoding is an unrecoverable framing error that must yield 400, so a 400 on that probe confirms the endpoint's framing validation and closes off the CL.CL variant there.
+  - **Disproof:** It is a real finding if the tier accepts the invalid Content-Length and forwards the message with the value intact, because that is precisely the precondition for the two-Content-Length variant. Note the spec's exception: a value that parses as a comma-separated list where every element is valid and all are identical is processed as that single value, so a probe using a consistent list is not invalid framing and a 400 there means something else - retry with a genuinely conflicting list before concluding.
+  - Sources: <https://portswigger.net/web-security/request-smuggling> · <https://www.rfc-editor.org/rfc/rfc9112.html>
+- RFC 9113 makes an HTTP/2 message carrying connection-specific headers such as transfer-encoding or upgrade malformed and requires Content-Length to equal the sum of DATA frame payloads, so a downgrade hop that tolerates these is where H2-to-H1 smuggling hides.
+  - **Disproof:** Refuted if the downgrade path rejects such a message at the first hop exactly as the spec prescribes, since a non-conforming tolerance is the condition being tested for.
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
+
+## Validation bar (how to prove it)
+
+- Request smuggling is proven only when a request the attacker never sent appears in the back-end access log, because a timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour.
+  - **Disproof:** If the back-end log contains exactly one request for that connection, the connection was not desynchronised and no smuggling occurred regardless of the response the attacker received. Equally, if the marker appears because the attacker genuinely sent a second request on a fresh connection, or because a retrying client resent the original, the log evidence is not attributable to the framing conflict and the claim collapses.
+  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://portswigger.net/web-security/request-smuggling>
 
 ## False-positive rules (when to reject it)
 
-- Reject a smuggling finding until it is distinguished from the adjacent behaviour this class also covers. "Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal." and "It basically enables you to hide a payload in plain sight." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- A front-end returning 400 for a request carrying both Transfer-Encoding and Content-Length is behaving exactly as HTTP/1.1 message parsing requires and must be logged as a negative control rather than as an unexploitable smuggling attempt.
+  - **Disproof:** It IS a real finding if the front-end accepts the ambiguous request and forwards it while the back-end resolves the conflict the other way - which you demonstrate by smuggling a second request and observing a response the attacker never sent. The disproof is the successful desynchronisation, not the absence of one: a 400 is only a clean negative when the request genuinely never reached the back-end, verifiable by the fact that no second request appears in back-end logs.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>
+- Concluding that a front-end and back-end disagree because one accepts and one drops a malformed header is a false positive unless the request was actually forwarded, since a dropped header at the edge never reaches the tier whose behaviour you are comparing.
+  - **Disproof:** It IS a real disagreement if the header demonstrably reaches the back-end - present in the origin's received headers or honoured as a distinct parameter there - and is simultaneously ignored, dropped, or treated as a duplicate by the front-end. Capture both hops or read both logs; if the header exists in only one, the layers never disagreed, and the header-name variant of this finding should be discarded rather than reported.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_core_module.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>
+- Reject a smuggling finding until it is distinguished from the adjacent behaviour this class also covers. "Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal." and "It basically enables you to hide a payload in plain sight." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible. _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "It basically enables you to hide a payload in plain sight." is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
+  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
 - A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.
   - **Disproof:** A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
 
+## Evidence requirements
+
... (truncated)
```

## 2026-10-04 00:43 — 197 diff lines
- items: 34 (supported 18), FP rules 3, chains 1, state mature

```diff
--- smuggling@current
+++ smuggling@new
@@ -20,135 +20,126 @@
 
 ## Prerequisites (do not start without these)
 
-- Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.
+- Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a desync is reproducible entirely within HTTP/2 with no downgrade involved, which would mean frame length is not enforced end to end.
   - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
 
 ## Recon signals (where to look)
 
-- Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.
+- Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
   - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
 
 ## Techniques (what to change)
 
-- It basically enables you to hide a payload in plain sight. _(unverified)_
+- HTTP request smuggling arises where a front-end and back-end disagree on where a request ends, so a smuggled request is prepended to the next legitimate user's request.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when a front end rejects ambiguous framing outright, or when both hops agree on message boundaries for the same request, leaving no request to smuggle.
+  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/quick-write-up.md>
+- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.  _(merged 3 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+- It basically enables you to hide a payload in plain sight.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
   - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- It does not indicate successful exploitation on patched devices. _(unverified)_
+- It does not indicate successful exploitation on patched devices.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
   - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- It does not indicate successful exploitation on patched devices. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
+- Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.
+  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
+- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.  _(merged 3 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
+- The grep -q guard prevents duplicate injection if the persistence mechanism is run again.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
-  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- It basically enables you to hide a payload in plain sight. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
-  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
-  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
-  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
-  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
-  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
-- The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.
+- The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if both hops resolve the same request boundary for the conflicting message, or if the front end strips the offending header before forwarding so the back end never sees the ambiguity.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/README.md>
-- The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.
+- The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if attacker-chosen Content-Length or Transfer-Encoding values survive verbatim into the downgraded request when observed downstream.
   - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
-- Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.
-  - **Disproof:** Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.
-  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
-- HTTP request smuggling arises where a front-end and back-end disagree on where a request ends, so a smuggled request is prepended to the next legitimate user's request.
-  - **Disproof:** Refuted when a front end rejects ambiguous framing outright, or when both hops agree on message boundaries for the same request, leaving no request to smuggle.
-  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/quick-write-up.md>
+- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
 
 ## Tests
 
-- An invalid or duplicated Content-Length with no Transfer-Encoding is an unrecoverable framing error that must yield 400, so a 400 on that probe confirms the endpoint's framing validation and closes off the CL.CL variant there.
+- An invalid or duplicated Content-Length with no Transfer-Encoding is an unrecoverable framing error that must yield 400, so a 400 on that probe confirms the endpoint's framing validation and closes off the CL.CL variant there.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is a real finding if the tier accepts the invalid Content-Length and forwards the message with the value intact, because that is precisely the precondition for the two-Content-Length variant. Note the spec's exception: a value that parses as a comma-separated list where every element is valid and all are identical is processed as that single value, so a probe using a consistent list is not invalid framing and a 400 there means something else - retry with a genuinely conflicting list before concluding.
   - Sources: <https://portswigger.net/web-security/request-smuggling> · <https://www.rfc-editor.org/rfc/rfc9112.html>
-- RFC 9113 makes an HTTP/2 message carrying connection-specific headers such as transfer-encoding or upgrade malformed and requires Content-Length to equal the sum of DATA frame payloads, so a downgrade hop that tolerates these is where H2-to-H1 smuggling hides.
+- RFC 9113 makes an HTTP/2 message carrying connection-specific headers such as transfer-encoding or upgrade malformed and requires Content-Length to equal the sum of DATA frame payloads, so a downgrade hop that tolerates these is where H2-to-H1 smuggling hides.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the downgrade path rejects such a message at the first hop exactly as the spec prescribes, since a non-conforming tolerance is the condition being tested for.
   - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
 
 ## Validation bar (how to prove it)
 
-- Request smuggling is proven only when a request the attacker never sent appears in the back-end access log, because a timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour.
+- Request smuggling is proven only when a request the attacker never sent appears in the back-end access log, because a timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the back-end log contains exactly one request for that connection, the connection was not desynchronised and no smuggling occurred regardless of the response the attacker received. Equally, if the marker appears because the attacker genuinely sent a second request on a fresh connection, or because a retrying client resent the original, the log evidence is not attributable to the framing conflict and the claim collapses.
   - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://portswigger.net/web-security/request-smuggling>
 
 ## False-positive rules (when to reject it)
 
-- A front-end returning 400 for a request carrying both Transfer-Encoding and Content-Length is behaving exactly as HTTP/1.1 message parsing requires and must be logged as a negative control rather than as an unexploitable smuggling attempt.
+- A front-end returning 400 for a request carrying both Transfer-Encoding and Content-Length is behaving exactly as HTTP/1.1 message parsing requires and must be logged as a negative control rather than as an unexploitable smuggling attempt.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS a real finding if the front-end accepts the ambiguous request and forwards it while the back-end resolves the conflict the other way - which you demonstrate by smuggling a second request and observing a response the attacker never sent. The disproof is the successful desynchronisation, not the absence of one: a 400 is only a clean negative when the request genuinely never reached the back-end, verifiable by the fact that no second request appears in back-end logs.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>
-- Concluding that a front-end and back-end disagree because one accepts and one drops a malformed header is a false positive unless the request was actually forwarded, since a dropped header at the edge never reaches the tier whose behaviour you are comparing.
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 34 (supported 18), FP rules 3, chains 1, state mature

```diff
--- smuggling@current
+++ smuggling@new
@@ -129,10 +129,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Establish the front-end/back-end disagreement first: CL.TE, TE.CL, or obfuscated header -- retry each a few times before concluding anything.
+2. Poison once and observe a second, unrelated user's request being affected; a self-inflicted desync is a lab artefact, not a finding.
 
 ### What counts as proof
 
```

## 2026-10-04 13:16 — 21 diff lines
- items: 35 (supported 19), FP rules 3, chains 1, state mature

```diff
--- smuggling@current
+++ smuggling@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 34 items, 18 supported, 3 FP rules, 1 chains
+> evidence: 35 items, 19 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Front-end and back-end disagree about where one request ends, so one request becomes two.
@@ -47,6 +47,9 @@
 - Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.
   - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
+- Public writeup evidence for smuggling: HTTP/2 framing WAF bypass.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
+  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://lab.ctbb.show/research/h2-WAF-Bypasses>
 - The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.  _(merged 3 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
```
