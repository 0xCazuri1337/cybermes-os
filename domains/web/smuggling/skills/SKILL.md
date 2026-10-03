---
name: smuggling-hunting
description: Use when hunting Request Smuggling / HTTP Desync in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Request Smuggling / HTTP Desync — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 444 · OWASP A04:2021
> evidence: 34 items, 18 supported, 3 FP rules, 1 chains
> maturity: **mature**

Front-end and back-end disagree about where one request ends, so one request becomes two.

**Also called:** request smuggling, http desync, cl te, te cl


## Prerequisites (do not start without these)

- Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.
  - **Disproof:** Refuted if a desync is reproducible entirely within HTTP/2 with no downgrade involved, which would mean frame length is not enforced end to end.
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>

## Recon signals (where to look)

- Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.
  - **Disproof:** If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Techniques (what to change)

- It basically enables you to hide a payload in plain sight. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- It does not indicate successful exploitation on patched devices. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- It does not indicate successful exploitation on patched devices. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- The grep -q guard prevents duplicate injection if the persistence mechanism is run again. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- It basically enables you to hide a payload in plain sight. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.
  - **Disproof:** Refuted if both hops resolve the same request boundary for the conflicting message, or if the front end strips the offending header before forwarding so the back end never sees the ambiguity.
  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/README.md>
- The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.
  - **Disproof:** Refuted if attacker-chosen Content-Length or Transfer-Encoding values survive verbatim into the downgraded request when observed downstream.
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
- Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.
  - **Disproof:** Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
- HTTP request smuggling arises where a front-end and back-end disagree on where a request ends, so a smuggled request is prepended to the next legitimate user's request.
  - **Disproof:** Refuted when a front end rejects ambiguous framing outright, or when both hops agree on message boundaries for the same request, leaving no request to smuggle.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/quick-write-up.md>

## Tests

- An invalid or duplicated Content-Length with no Transfer-Encoding is an unrecoverable framing error that must yield 400, so a 400 on that probe confirms the endpoint's framing validation and closes off the CL.CL variant there.
  - **Disproof:** It is a real finding if the tier accepts the invalid Content-Length and forwards the message with the value intact, because that is precisely the precondition for the two-Content-Length variant. Note the spec's exception: a value that parses as a comma-separated list where every element is valid and all are identical is processed as that single value, so a probe using a consistent list is not invalid framing and a 400 there means something else - retry with a genuinely conflicting list before concluding.
  - Sources: <https://portswigger.net/web-security/request-smuggling> · <https://www.rfc-editor.org/rfc/rfc9112.html>
- RFC 9113 makes an HTTP/2 message carrying connection-specific headers such as transfer-encoding or upgrade malformed and requires Content-Length to equal the sum of DATA frame payloads, so a downgrade hop that tolerates these is where H2-to-H1 smuggling hides.
  - **Disproof:** Refuted if the downgrade path rejects such a message at the first hop exactly as the spec prescribes, since a non-conforming tolerance is the condition being tested for.
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>

## Validation bar (how to prove it)

- Request smuggling is proven only when a request the attacker never sent appears in the back-end access log, because a timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour.
  - **Disproof:** If the back-end log contains exactly one request for that connection, the connection was not desynchronised and no smuggling occurred regardless of the response the attacker received. Equally, if the marker appears because the attacker genuinely sent a second request on a fresh connection, or because a retrying client resent the original, the log evidence is not attributable to the framing conflict and the claim collapses.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://portswigger.net/web-security/request-smuggling>

## False-positive rules (when to reject it)

- A front-end returning 400 for a request carrying both Transfer-Encoding and Content-Length is behaving exactly as HTTP/1.1 message parsing requires and must be logged as a negative control rather than as an unexploitable smuggling attempt.
  - **Disproof:** It IS a real finding if the front-end accepts the ambiguous request and forwards it while the back-end resolves the conflict the other way - which you demonstrate by smuggling a second request and observing a response the attacker never sent. The disproof is the successful desynchronisation, not the absence of one: a 400 is only a clean negative when the request genuinely never reached the back-end, verifiable by the fact that no second request appears in back-end logs.
  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>
- Concluding that a front-end and back-end disagree because one accepts and one drops a malformed header is a false positive unless the request was actually forwarded, since a dropped header at the edge never reaches the tier whose behaviour you are comparing.
  - **Disproof:** It IS a real disagreement if the header demonstrably reaches the back-end - present in the origin's received headers or honoured as a distinct parameter there - and is simultaneously ignored, dropped, or treated as a duplicate by the front-end. Capture both hops or read both logs; if the header exists in only one, the layers never disagreed, and the header-name variant of this finding should be discarded rather than reported.
  - Sources: <https://nginx.org/en/docs/http/ngx_http_core_module.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>
- Reject a smuggling finding until it is distinguished from the adjacent behaviour this class also covers. "Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal." and "It basically enables you to hide a payload in plain sight." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible. _(unverified)_
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "It basically enables you to hide a payload in plain sight." is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.
  - **Disproof:** A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>

## Evidence requirements

- A convincing observation for this class is: The useful next question is which layer decided, not what the status code was.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack) states the full boundary.
  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>
- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: It basically enables you to hide a payload in plain sight. _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smuggling.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>

## Impact framing

- The payoff of a successful smuggle is response control: the attacker makes the shared connection deliver a response computed for their own smuggled request to a different client, which is both the proof of the desync and the theft of the victim's response.
  - **Disproof:** Refuted if the smuggled request's response always returns on the connection that sent it, or if the desync only ever shows up as connection errors with no cross-client response delivery observed.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>

## Variants

- When a front end and back end disagree about connection reuse rather than message framing, the defect is a connection-state or routing mismatch, so testing for CL.TE and TE.CL header ambiguity will never surface it.
  - **Disproof:** Refuted if the desync reproduces from a single unambiguous request with consistent framing and no Transfer-Encoding, which puts the cause back in message framing.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-connection-request-smuggling.md>
- A chain that shows no CL.TE or TE.CL ambiguity still has sub-forms left to test - the ones that rely on connection reuse, connection state, or the client - so a clean header-desync result does not close the hunt.
  - **Disproof:** Refuted if no desync can be induced by any manipulation of connection reuse or by a client-side mismatch, meaning the reuse-dependent forms are absent from that chain.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
- A request carrying Transfer-Encoding: gzip can desynchronise a chain even with no classic CL.TE split, because one hop still honours Content-Length while another treats the message as illegally framed, making the unexpected encoding value a desync probe on its own.
  - **Disproof:** Refuted if both hops reject the gzip-coded message identically with a 400 for attacker and victim alike, or if the intermediary strips the encoding and the back end sees clean framing.
  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/README.md>

## Defence bypasses

- A Transfer-Encoding whose final coding is not chunked makes the message body length underivable, so a front-end that only special-cases the literal value chunked can be pushed into framing with a different layer than the back-end uses.
  - **Disproof:** It is blocked when the front-end and back-end both reject the variant, or when the front-end's parser correctly identifies the coding list and either honours the transfer encoding or rejects the message - a 400 at the edge with no forwarded request. Also note that many modern servers normalise or hard-code the strict behaviour; verify the actual version rather than assuming the classic bypass still applies, and confirm the discrepancy with the log-based proof before reporting.
  - Sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://www.rfc-editor.org/rfc/rfc9112.html>

---
Full class document: `domains/web/smuggling/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smuggling`
