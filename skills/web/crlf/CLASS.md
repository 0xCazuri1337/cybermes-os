<!-- GENERATED from db/wks.db — do not edit -->
# CRLF / Header Injection

## Definition

User input reaches a header or line boundary the protocol treats as a delimiter.

- **CWE:** 93
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["crlf injection", "header injection", "response splitting"]

Canonical home for `crlf`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**CRLF/response-splitting requires an untrusted value to reach a response header value or a response body position where the HTTP serializer emits a line terminator.**

Map it first: for each candidate endpoint, find the parameter that ends up in a `Location`, `Set-Cookie`, `Refresh`, `X-` custom, or `Content-Type` header, or that is concatenated ahead of a body. Cloudflare's Pingora disclosure is the canonical shape of the outcome: a smuggled request could inject headers and its URL into a subsequent valid request on the same connection, i.e. attacker bytes became response header lines rather than header values. GitHub Security Lab's encoding writeup supplies the defensive half: unexpected newline characters may be introduced specifically to bypass brittle validation, so normalize or encode input so it represents a single line BEFORE validating. Hunting procedure: `GET /redirect?next=<payload>` and `GET /download?fn=<payload>` with a valid session, then read the FULL raw response including every header line and the blank line before the body. If no untrusted value reaches a header or a body-prefix position, the class does not apply to that endpoint.

*Disproof:* If code review plus observation shows every attacker-influenced value is either (a) never written to a response header, or (b) passed through a CRLF-stripping encoder before the serializer runs, then no attacker byte can reach a line-terminator position and the claim is false. Concretely: a payload of `%0d%0aX-Injected:%20yes` sent to every such parameter returns a response with no `X-Injected` header and no second header block, on every parameter tested.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**The signal for CRLF is a differential: a raw CR/LF and its percent-encoded %0d%0a form produce different header structure, and only one of them is rejected.**

Send the same logical payload three ways to the same parameter and diff the RAW response: (1) literal CRLF using curl's `--data-binary` with an actual 0x0d 0x0a, (2) `%0d%0a` percent-encoded, (3) a single encoded `%0a` and separately `%0d`. Read the status line, the full header block, the terminating blank line, and the first body bytes. Interpret: if (2) yields an extra header or a truncated body while (1) is rejected or neutralised, the filter sees the literal control characters but not the encoded form, which is the classic bypass. If both are neutralised the endpoint is filtering. If (1) splits and (2) does not, the filter is decoding. Google's webmaster security guidance frames why percent-encoding is the interesting case: a URL that looks harmless is not, because decoding the percent-encoded characters yields the live payload. GitHub's encoding writeup gives the fix shape: use single-line anchors in the validation regex, which only works if you normalized first.

*Disproof:* If raw CRLF, %0d%0a, %0a and %0d all produce byte-identical header structure and identical body framing on every response, there is no differential and therefore no signal. One clean way to disprove: a single request with `%0d%0aX-Injected: yes` returns exactly one header block, no `X-Injected`, and the same body as the control request with `x` in that position.

**The convincing CRLF evidence is a stored value containing a literal carriage-return/line-feed pair that reappears in a replayed header line, which distinguishes a genuine finding from the far more common case of a header value containing only percent-encoded %0d%0a that the server never decoded.**

Mechanism: The convincing CRLF evidence is a stored value containing a literal carriage-return/line-feed pair that reappears in a replayed header line, which distinguishes a genuine finding from the far more common case of a header value containing only percent-encoded %0d%0a that the server never decoded. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the application performs a single decode of the stored value immediately before header construction — then a percent-encoded payload in the submitted input still produces literal CRLF on the wire, and the encoded form alone is sufficient evidence provided the decode step is shown.

*Disproof:* The claim is false when the application performs a single decode of the stored value immediately before header construction — then a percent-encoded payload in the submitted input still produces literal CRLF on the wire, and the encoded form alone is sufficient evidence provided the decode step is shown.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.**

Derived from crlf.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (crlf.fp_rule.auto.derived) states the full boundary.

**A convincing observation for this class is: The separating observation is WHERE in the response those bytes are.**

Derived from crlf.fp.percent-encoded-crlf-reflected-in-body, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (crlf.fp.percent-encoded-crlf-reflected-in-body) states the full boundary.

## Exploitation

**This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins.**

ss HTTP / 1.1 // 
 Host : victim . example . com 
 Thus, the smuggled request could inject headers and its URL into a subsequent valid request sent on the same connection to a Pingora reverse proxy service. CDN request smuggling and hijacking On April 11, 2025, Cloudflare was in the process of rolling out a Pingora proxy component with caching support enabled to a subset of CDN free plan traffic. This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins. As previously noted, the security researcher reported that they were also able to cause visitors to Cloudflare sites to make subsequent requests to their own malicious origin and observe which site URLs the visitor was originally attempting to access. During our investigation, Cloudflare found that certain origin servers would be susceptible to this secondary attack effect. The smuggled request i

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This component was vulnerable to this request smuggling attack, which could enable modifyi".

**The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect.**

t to customer origins. As previously noted, the security researcher reported that they were also able to cause visitors to Cloudflare sites to make subsequent requests to their own malicious origin and observe which site URLs the visitor was originally attempting to access. During our investigation, Cloudflare found that certain origin servers would be susceptible to this secondary attack effect. The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect. Continuing from the prior example: GET / HTTP / 1.1 // 
 Host : attacker . example . com 
 Bogus : fooGET / victim / main . css HTTP / 1.1 // 
 Host : victim . example . com 
 
 
 HTTP / 1.1 301 Moved Permanently // 
 Location : https : //attacker.example.com/ 
 When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The smuggled request in the example above would be sent to the correct origin IP address p".

**When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access.**

IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect. Continuing from the prior example: GET / HTTP / 1.1 // 
 Host : attacker . example . com 
 Bogus : fooGET / victim / main . css HTTP / 1.1 // 
 Host : victim . example . com 
 
 
 HTTP / 1.1 301 Moved Permanently // 
 Location : https : //attacker.example.com/ 
 When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access. GET / HTTP / 1.1 // 
 Host : attacker . example . com 
 Referrer : https : //victim.example.com/victim/main.css 
 Upon verifying the Pingora proxy component was susceptible, the team immediately disabled CDN traffic to the vulnerable component on 2025-04-12 06:44 UTC to stop possible exploitation. By 2025-04-19 01:56 UTC and prior to re-enablement of any traffic to the vulnerable component, a pat

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When the client browser followed the redirect, it would trigger this attack by s”) does not occur under a test that isolates that control.

**When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access.**

IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect. Continuing from the prior example: GET / HTTP / 1.1 // 
 Host : attacker . example . com 
 Bogus : fooGET / victim / main . css HTTP / 1.1 // 
 Host : victim . example . com 
 
 
 HTTP / 1.1 301 Moved Permanently // 
 Location : https : //attacker.example.com/ 
 When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access. GET / HTTP / 1.1 // 
 Host : attacker . example . com 
 Referrer : https : //victim.example.com/victim/main.css 
 Upon verifying the Pingora proxy component was susceptible, the team immediately disabled CDN traffic to the vulnerable component on 2025-04-12 06:44 UTC to stop possible exploitation. By 2025-04-19 01:56 UTC and prior to re-enablement of any traffic to the vulnerable component, a pat

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When the client browser followed the redirect, it would trigger this attack by s”) does not occur under a test that isolates that control.

**This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins.**

ss HTTP / 1.1 // 
 Host : victim . example . com 
 Thus, the smuggled request could inject headers and its URL into a subsequent valid request sent on the same connection to a Pingora reverse proxy service. CDN request smuggling and hijacking On April 11, 2025, Cloudflare was in the process of rolling out a Pingora proxy component with caching support enabled to a subset of CDN free plan traffic. This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins. As previously noted, the security researcher reported that they were also able to cause visitors to Cloudflare sites to make subsequent requests to their own malicious origin and observe which site URLs the visitor was originally attempting to access. During our investigation, Cloudflare found that certain origin servers would be susceptible to this secondary attack effect. The smuggled request i

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This component was vulnerable to this request smuggling attack, which could enable modifyi".

**The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect.**

t to customer origins. As previously noted, the security researcher reported that they were also able to cause visitors to Cloudflare sites to make subsequent requests to their own malicious origin and observe which site URLs the visitor was originally attempting to access. During our investigation, Cloudflare found that certain origin servers would be susceptible to this secondary attack effect. The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect. Continuing from the prior example: GET / HTTP / 1.1 // 
 Host : attacker . example . com 
 Bogus : fooGET / victim / main . css HTTP / 1.1 // 
 Host : victim . example . com 
 
 
 HTTP / 1.1 301 Moved Permanently // 
 Location : https : //attacker.example.com/ 
 When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The smuggled request in the example above would be sent to the correct origin IP address p".

**Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.**

The reflected value is the first observable step only if it is later re-emitted through a header-emitting API — stored and replayed by a Location or Set-Cookie header, or re-serialised by a downstream proxy/CDN into a response header. Record the byte position of the payload relative to the header/body boundary before classifying anything. This looks like CRLF injection (a %0d%0a payload comes back verbatim) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.

*Disproof:* Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no Set-Cookie (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.

**Response splitting succeeds when attacker bytes are emitted as a new header line inside a response whose Content-Type and framing still let a second header block or injected header be honoured.**

Craft: `GET /go?u=x HTTP/1.1` with a parameter that lands in `Location`, and payload `x%0d%0aSet-Cookie:%20pwn=1%0d%0a%0d%0a<script>alert(1)</script>`. Read the raw response as bytes, not through a client library that normalises headers. A genuine split shows TWO header blocks: the original response ends at the injected blank line and a complete second response follows, or at minimum an injected header line appears before the real blank line. GitHub's post-CSP writeup supplies a real captured instance of exactly this byte pattern - a request URL in which every CRLF is percent-encoded, `%0D%0A`, threading an injected `</textarea>`, an injected `<form action="/logout">` and a hidden `authenticity_token` field between them. CrowdStrike's rootkit writeup shows why the framing side matters: the injector only proceeds when the response Content-Type and the attacker-specified Content-Type match, and it handles both chunked Transfer-Encoding and gzip Content-Encoding, so a split must be judged against the encoded body too. Test the chunked and gzip variants separately; a split that only reproduces with Content-Encoding: gzip is still a split.

*Disproof:* If the raw response contains exactly one header block, ends at a single blank line, contains no injected header, and has a body identical to the control request's body, response splitting did not occur. Repeat for the raw-CRLF, %0d%0a, chunked and gzip variants; if all four come back structurally identical with no injected header, the claim is false for that endpoint.

## Variations

**Modern language-level header setters defeat naive CRLF payloads without any application sanitiser, because a value containing CR or LF raises a TypeError instead of being serialised, so a payload that is not percent-decoded twice and not split-and-rejoined before reaching the setter cannot inject a header.**

Mechanism: Modern language-level header setters defeat naive CRLF payloads without any application sanitiser, because a value containing CR or LF raises a TypeError instead of being serialised, so a payload that is not percent-decoded twice and not split-and-rejoined before reaching the setter cannot inject a header. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the value is passed through a path that bypasses the guarded setter — a raw write to the socket, a C library or framework API that takes a pre-built header block, a template or config file that emits headers, or a reverse proxy that re-serialises a stored value — because those paths re-introduce the injection the TypeError was meant to prevent.

*Disproof:* The rule is wrong when the value is passed through a path that bypasses the guarded setter — a raw write to the socket, a C library or framework API that takes a pre-built header block, a template or config file that emits headers, or a reverse proxy that re-serialises a stored value — because those paths re-introduce the injection the TypeError was meant to prevent.

**A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.**

The bypass is a decode-order defect, not a filter weakness. Step 1: the application validates the raw string with a single-line anchored pattern, so `%0d%0a` contains no control byte and passes - GitHub Security Lab's encoding writeup names this exact shape, noting unexpected newline characters may be introduced to bypass brittle validation and that the fix is to normalize or encode the input to a single line BEFORE validating, with single-line anchors in the regex. Step 2: something downstream - a router, a redirect helper, a framework's header writer, a proxy - percent-decodes before the value reaches the HTTP serializer. Step 3: the serializer now sees a real 0x0d 0x0a in a header value and emits a header line break. Hunt it with a three-way differential on the same parameter: literal CRLF, %0d%0a, and %250d%250a (double-encoded). The double-encoded case is the discriminator - if the validator rejects literal, accepts %0d%0a and produces an injected header, and accepts %250d%250a which a second decode turns into the same injected header, the decode order is the bug. Chain it: the same defect in a `Location` or `Set-Cookie` value is what turns a validation gap into response splitting, and a split in front of a shared cache is what turns it into cache poisoning.

*Disproof:* Disproof is a uniform rejection: literal CRLF, %0d%0a, %0a, %0d and %250d%250a all produce the same control response - one header block, no injected header, unchanged body. If the endpoint normalizes or rejects after decoding rather than only before, the bypass is closed and this claim is false. Equivalently, if the injected header only appears in a downstream component the attacker cannot reach, the practical bypass does not exist.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.crlf.auto.01` — crlf: observe, exercise, confirm (goal: `Establish, exercise and confirm a crlf condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.**

The false positive: a scanner sends `?q=%0d%0aSet-Cookie:%20pwn=1`, gets back a page containing the literal string `Set-Cookie: pwn=1` in the HTML, and reports response splitting. The separating observation is WHERE in the response those bytes are. If they appear in the body - after the terminating blank line - the browser's HTML parser treats them as text or as an attribute, not as a header, and no cookie is set. CRLF injection requires the terminator to be honoured by the HTTP message serializer, i.e. to land inside a header value or at a position the serializer writes unescaped, BEFORE the blank line. Google's guidance is the canonical illustration of why the encoded form is worth chasing but not worth reporting on sight: a URL that looks harmless becomes live once the percent-encoded characters are decoded - into HTML in that example, which is a body-context bug, not a header-context one. CrowdStrike's rootkit analysis supplies the positive test: real response injection requires the response Content-Type and the attacker's specified Content-Type to match before injection proceeds. So: parse the raw response into status line, header block, blank line, body. Only a match in the header block, or an extra header block, is a finding.

*Disproof:* Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no `Set-Cookie` (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.

**A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line.**

Mechanism: A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the Location value reaches the wire with a real CR/LF pair split into an additional header line, or when the redirect is emitted by a different component (a proxy, a CDN edge function, a web-server rewrite rule) than the one whose setter the tester assumed was sanitising the value.

*Disproof:* The rule is wrong when the Location value reaches the wire with a real CR/LF pair split into an additional header line, or when the redirect is emitted by a different component (a proxy, a CDN edge function, a web-server rewrite rule) than the one whose setter the tester assumed was sanitising the value.

**Reject a crlf finding until it is distinguished from the adjacent behaviour this class also covers. "When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious..." and "A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious...

Adjacent behaviour that produces the same observable result: A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A CRLF finding is validated by showing that a line terminator survives" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.**

Mechanism: Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the reflected value is later re-emitted through a header-emitting API — for example the payload is stored and replayed by a Location or Set-Cookie header, or a downstream proxy/CDN re-serializes the stored value into a response header — in which case the body reflection is the first observable step of real header injection.

*Disproof:* The rule is wrong when the reflected value is later re-emitted through a header-emitting API — for example the payload is stored and replayed by a Location or Set-Cookie header, or a downstream proxy/CDN re-serializes the stored value into a response header — in which case the body reflection is the first observable step of real header injection.

## Validation

**CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.**

Mechanism: CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false if the client used transparently normalises or de-duplicates repeated header fields (many HTTP libraries fold duplicates into a comma list), in which case the injection genuinely occurred but the evidence must come from a raw socket capture or a Wireshark/mitmproxy view rather than the library's parsed headers.

*Disproof:* The claim is false if the client used transparently normalises or de-duplicates repeated header fields (many HTTP libraries fold duplicates into a comma list), in which case the injection genuinely occurred but the evidence must come from a raw socket capture or a Wireshark/mitmproxy view rather than the library's parsed headers.

**A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.**

Two-part validation. Part one, survival: replay the payload and assert on raw bytes that a second header line or a second header block exists. Assert on the bytes; a client library that raises on a malformed response is itself evidence, not a reason to discard the result. Part two, framing. Re-run the same payload with `Accept-Encoding: gzip` and separately with a chunked request, and inspect the decoded body. CrowdStrike's rootkit analysis is the reference for why framing must be checked explicitly: the injector handles both chunked Transfer-Encoding and gzip Content-Encoding, so the same injected bytes can be invisible in a decoded view and present on the wire. GitHub's encoding writeup supplies the control-side assertion: validation must use single-line anchors, which is only meaningful if the input was normalized or encoded to a single line first, and encoding adds real friction. A finding that only reproduces in one framing mode is still a finding - record which mode, because that is what tells the defender where the fix belongs.

*Disproof:* Disproof is a raw response in which the line terminator never appears: one header block, one blank line, no injected header, and a body whose decoded content equals the control response's decoded body. If that holds across identity, gzip and chunked framings for both the literal-CRLF and %0d%0a payloads, the CRLF did not survive and the finding is not validated.

**To decide this case, observe: Mechanism: A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line.**

Derived from crlf.fp_rule.a_redirect_status_without_an_extra_header_line_is_not_proof_of_injection, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.fp_rule.a_redirect_status_without_an_extra_header_line_is_not_proof_of_injection) states the full boundary.

**To decide this case, observe: Mechanism: CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.**

Derived from crlf.validation.a_new_response_line_is_proved_by_a_second_header_pair_in_the_raw_response, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.validation.a_new_response_line_is_proved_by_a_second_header_pair_in_the_raw_response) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from crlf.bypass.a_language_level_header_api_that_sanitizes_defeats_the_injection_before_the_wire, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.bypass.a_language_level_header_api_that_sanitizes_defeats_the_injection_before_the_wire) states the full boundary.

**To decide this case, observe: Mechanism: Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.**

Derived from crlf.fp_rule.crlf_payload_reflected_in_a_body_or_error_page_is_not_header_injection, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.fp_rule.crlf_payload_reflected_in_a_body_or_error_page_is_not_header_injection) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.cloudflare.com** (vendor_advisory)
  - <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora>
- **crowdstrike.com** (writeup)
  - <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **github.blog** (writeup)
  - <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
  - <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>
- **httpd.apache.org** (writeup)
  - <https://httpd.apache.org/docs/2.4/mod/mod_headers.html>
- **nodejs.org** (writeup)
  - <https://nodejs.org/api/http.html>
- **php.net** (writeup)
  - <https://www.php.net/manual/en/function.header.php>
- **security.googleblog.com** (docs)
  - <https://security.googleblog.com/2011/05/website-security-for-webmasters.html>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
