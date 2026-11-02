# Methodology — Request Smuggling / HTTP Desync

> Derived from 19 verified items. Regenerate with `python -m wks.methodgen --class smuggling --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Front-end and back-end disagree about where one request ends, so one request becomes two.

**References.** CWE-444 · A04:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.**

Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.

HackTricks reference: Request Smuggling in HTTP/2 Downgrades (pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

- *Disproof:* Refuted if a desync is reproducible entirely within HTTP/2 with no downgrade involved, which would mean frame length is not enforced end to end.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.**

Exploitation of edge appliances commonly begins with a request for a static administrative asset path that a normal client would not fetch. Because the request is a plain GET for a file, filtering and rate limiting rarely treat it as hostile, which is precisely why it survives to the vulnerable handler. Two properties make it useful to a defender: the path is predictable enough to hunt for in logs, and an attacker probing from rotating infrastructure produces a scattered request pattern for one static path, which is anomalous even though each individual request is unremarkable.

- *Disproof:* If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
- *Evidence:* high_confidence — [blog.trailofbits.com](https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.**

The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.

HackTricks reference: HTTP Request Smuggling / HTTP Desync Attack (pentesting-web/http-request-smuggling/README.md)

- *Disproof:* Refuted if both hops resolve the same request boundary for the conflicting message, or if the front end strips the offending header before forwarding so the back end never sees the ambiguity.
- *Evidence:* high_confidence — [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/README.md); [tomcat.apache.org](https://tomcat.apache.org/tomcat-9.0-doc/config/http.html)

**The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.**

The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.

HackTricks reference: Request Smuggling in HTTP/2 Downgrades (pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

- *Disproof:* Refuted if attacker-chosen Content-Length or Transfer-Encoding values survive verbatim into the downgraded request when observed downstream.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

**HTTP request smuggling arises where a front-end and back-end disagree on where a request ends, so a smuggled request is prepended to the next legitimate user's request.**

In practice on HTB this shows up as:  [https://www.cvedetails.com/vulnerability-list/vendor\_id-10410/product\_id-34824/Eclipse-Jetty.html](https://www.cvedetails.com/vulnerability-list/vendor_id-10410/product_id-34824/Eclipse-Jetty.html)
 [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
![](../../.gitbook/assets/30-printer-auth%20%281%29%20%281%29%20%281%29%20%281%29%20%281%29%20%281%29%20%281%29%20%281%29%20%281%29.png)

Write-up provenance: zweilosec/htb-writeups :: linux-machines/hard/quick-write-up.md (7325 words, classified network).

- *Disproof:* Refuted when a front end rejects ambiguous framing outright, or when both hops agree on message boundaries for the same request, leaving no request to smuggle.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/444.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/quick-write-up.md)

**Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.**

Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.

HackTricks reference: HTTP Response Smuggling / Desync (pentesting-web/http-response-smuggling-desync.md)

- *Disproof:* Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/444.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md)

**Public writeup evidence for smuggling: HTTP/2 framing WAF bypass.**

HARVESTED FROM bugbountydaily RSS -> https://lab.ctbb.show/research/h2-WAF-Bypasses
Reason it matters: HTTP/2 framing WAF bypass.

The proxy sends a sub-request to an auth service containing only the request headers - because that is where authentication data lives (Authorization headers, cookies, session tokens).

- *Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/444.html); [lab.ctbb.show](https://lab.ctbb.show/research/h2-WAF-Bypasses)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Request smuggling is proven only when a request the attacker never sent appears in the back-end access log, because a timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour.**

CWE-444 defines the weakness as an intermediary failing to interpret malformed messages consistently with the entities at the ultimate destination - the harm is not in the malformed request, it is in the second, unintended request that the disagreement created. So the evidence has to be that second request: a distinctive path or marker showing up in the origin's access log as belonging to a connection the attacker opened for one request. PortSwigger's consequence list separates the two effects, response queue desynchronisation and stealing other users' responses, and both are downstream of the same proof. In the field this is why a proxy that times out on the probe is not a negative: it is the expected first symptom of a persistent-connection poisoning attempt and should be followed by the log check that decides it.

- *Disproof:* If the back-end log contains exactly one request for that connection, the connection was not desynchronised and no smuggling occurred regardless of the response the attacker received. Equally, if the marker appears because the attacker genuinely sent a second request on a fresh connection, or because a retrying client resent the original, the log evidence is not attributable to the framing conflict and the claim collapses.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/444.html); [portswigger.net](https://portswigger.net/web-security/request-smuggling)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.**

The observation is a tiny HTML attachment that appears inert to mail and web filters, contains an encoded blob, and reconstructs a payload client-side, which is filed under smuggling because the payload crosses a boundary unseen by the filter. It is a different class. HTML smuggling operates entirely inside one browser and one origin: the sender hid the payload inside image polyglots, called the PNG or GIF files from remote so the HTML stays small, and added dynamic XOR encryption to the payloads hidden inside the image. No intermediary parses two conflicting request framings. HTTP request smuggling is a disagreement between a front-end and back-end HTTP parser over where one request ends and the next begins; a real instance looks like a server whose REST parser incorrectly handles pipelined HTTP requests, which allows successive requests to overwrite the previously parsed HTTP method, URL and body, and is filed as inconsistent interpretation of HTTP requests (CWE-444). The distinguishing test is where the payload boundary is drawn: for HTML smuggling, one request and one response, and the payload materializes in the DOM; for smuggling, two requests where the victim's request is prefixed to or swallowed by the attacker's. Classify on the parser disagreement, not on the payload being hidden.

- *Disproof:* A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577)

**Concluding that a front-end and back-end disagree because one accepts and one drops a malformed header is a false positive unless the request was actually forwarded, since a dropped header at the edge never reaches the tier whose behaviour you are comparing.**

This is the header-name analogue of the CL/TE case and it is the single most over-reported finding in the class. nginx controls whether header fields with invalid names should be ignored, and its underscores handling marks names containing underscores as invalid, making them subject to that directive - so with the default configuration an underscore-bearing header may be dropped or the request rejected at the edge. Tomcat's rejectIllegalHeader default rejects the whole request. In both cases the request stops there. Comparing the front-end's acceptance of a header against a back-end you never reached, or against a log line that shows the header was already stripped, is not evidence of parsing disagreement. Establish forwarding first, then compare.

- *Disproof:* It IS a real disagreement if the header demonstrably reaches the back-end - present in the origin's received headers or honoured as a distinct parameter there - and is simultaneously ignored, dropped, or treated as a duplicate by the front-end. Capture both hops or read both logs; if the header exists in only one, the layers never disagreed, and the header-name variant of this finding should be discarded rather than reported.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_core_module.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9112.html)

**A front-end returning 400 for a request carrying both Transfer-Encoding and Content-Length is behaving exactly as HTTP/1.1 message parsing requires and must be logged as a negative control rather than as an unexploitable smuggling attempt.**

RFC 9112 states that when both fields are present the Transfer-Encoding overrides the Content-Length, that such a message might indicate an attempt to perform request smuggling, and that it ought to be handled as an error. 'Ought to be handled as an error' means the rejection is the correct behaviour, so a 400 tells you the front-end normalises or refuses the ambiguity - it does not tell you the front-end and back-end disagree. The hunter's mistake is to file a 400 as a partial success because it feels like the payload reached something. It did not: it was discarded at the framing layer, before any request was forwarded, so no desynchronisation occurred. The useful next question is which layer decided, not what the status code was.

- *Disproof:* It IS a real finding if the front-end accepts the ambiguous request and forwards it while the back-end resolves the conflict the other way - which you demonstrate by smuggling a second request and observing a response the attacker never sent. The disproof is the successful desynchronisation, not the absence of one: a 400 is only a clean negative when the request genuinely never reached the back-end, verifiable by the fact that no second request appears in back-end logs.
- *Evidence:* high_confidence — [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9112.html); [tomcat.apache.org](https://tomcat.apache.org/tomcat-9.0-doc/config/http.html)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A Transfer-Encoding whose final coding is not chunked makes the message body length underivable, so a front-end that only special-cases the literal value chunked can be pushed into framing with a different layer than the back-end uses.**

RFC 9112 is explicit about the consequence: if Transfer-Encoding is present in a request and chunked is not the final encoding, the message body length cannot be determined reliably and the server must respond 400 and close. Sending gzip, chunked or an obfuscated variant such as a spaced or otherwise non-canonical spelling of chunked tests whether the front-end's check is a strict comparison against the canonical token or a real parse of the coding list. A front-end that treats an unrecognised coding as 'no transfer encoding' and falls back to Content-Length while the back-end parses the coding list is exactly the CWE-444 pattern. The field probe is small: send one request per coding-list variant and note which status and which framing each tier implies.

- *Disproof:* It is blocked when the front-end and back-end both reject the variant, or when the front-end's parser correctly identifies the coding list and either honours the transfer encoding or rejects the message - a 400 at the edge with no forwarded request. Also note that many modern servers normalise or hard-code the strict behaviour; verify the actual version rather than assuming the classic bypass still applies, and confirm the discrepancy with the log-based proof before reporting.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/444.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9112.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 7. Impact

_What is actually demonstrable, and what to stop claiming._

**The payoff of a successful smuggle is response control: the attacker makes the shared connection deliver a response computed for their own smuggled request to a different client, which is both the proof of the desync and the theft of the victim's response.**

The payoff of a successful smuggle is response control: the attacker makes the shared connection deliver a response computed for their own smuggled request to a different client, which is both the proof of the desync and the theft of the victim's response.

HackTricks reference: HTTP Response Smuggling / Desync (pentesting-web/http-response-smuggling-desync.md)

- *Disproof:* Refuted if the smuggled request's response always returns on the connection that sent it, or if the desync only ever shows up as connection errors with no cross-client response delivery observed.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/444.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
