# CRLF / Header Injection

> surface: `web` · CWE: 93 · OWASP: A03:2021
> maturity: **researching** — 23 items, 10 supported, 0 FP rules, 1 chains

User input reaches a header or line boundary the protocol treats as a delimiter.

**Aliases:** crlf injection, header injection, response splitting

## Prerequisite

- **CRLF/response-splitting requires an untrusted value to reach a response header value or a response body position where the HTTP serializer emits a line terminator.**  
  `high_confidence` · score 0.984 · disproved by: If code review plus observation shows every attacker-influenced value is either (a) never written to a response header, or (b) passed through a CRLF-stripping encoder before the serializer runs, then no attacker byte can reach a line-terminator position and the claim is false. Concretely: a payload of `%0d%0aX-Injected:%20yes` sent to every such parameter returns a response with no `X-Injected` header and no second header block, on every parameter tested.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>

## Signal

- **The signal for CRLF is a differential: a raw CR/LF and its percent-encoded %0d%0a form produce different header structure, and only one of them is rejected.**  
  `high_confidence` · score 0.954 · disproved by: If raw CRLF, %0d%0a, %0a and %0d all produce byte-identical header structure and identical body framing on every response, there is no differential and therefore no signal. One clean way to disprove: a single request with `%0d%0aX-Injected: yes` returns exactly one header block, no `X-Injected`, and the same body as the control request with `x` in that position.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>

## Technique

- **Response splitting succeeds when attacker bytes are emitted as a new header line inside a response whose Content-Type and framing still let a second header block or injected header be honoured.**  
  `high_confidence` · score 0.929 · disproved by: If the raw response contains exactly one header block, ends at a single blank line, contains no injected header, and has a body identical to the control request's body, response splitting did not occur. Repeat for the raw-CRLF, %0d%0a, chunked and gzip variants; if all four come back structurally identical with no injected header, the claim is false for that endpoint.
  sources: <https://github.blog/engineering/platform-security/githubs-post-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access.**  
  `high_confidence` · score 0.8845 · disproved by: Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When the client browser followed the redirect, it would trigger this attack by s”) does not occur under a test that isolates that control.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.php.net/manual/en/function.header.php>
- **Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.**  
  `high_confidence` · score 0.882 · disproved by: Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no Set-Cookie (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect.**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The smuggled request in the example above would be sent to the correct origin IP address p".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.php.net/manual/en/function.header.php>
- **This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins.**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This component was vulnerable to this request smuggling attack, which could enable modifyi".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Test

- **To decide this case, observe: Mechanism: Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.**  
  `under_review` · score 0.893 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.fp_rule.crlf_payload_reflected_in_a_body_or_error_page_is_not_header_injection) states the full boundary.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://nodejs.org/api/http.html>
- **To decide this case, observe: Mechanism: A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line.**  
  `under_review` · score 0.8655 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.fp_rule.a_redirect_status_without_an_extra_header_line_is_not_proof_of_injection) states the full boundary.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.php.net/manual/en/function.header.php>
- **To decide this case, observe: Mechanism: CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.**  
  `under_review` · score 0.8655 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (crlf.validation.a_new_response_line_is_proved_by_a_second_header_pair_in_the_raw_response) states the full boundary.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://nodejs.org/api/http.html>

## Validation

- **A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.**  
  `high_confidence` · score 0.929 · disproved by: Disproof is a raw response in which the line terminator never appears: one header block, one blank line, no injected header, and a body whose decoded content equals the control response's decoded body. If that holds across identity, gzip and chunked framings for both the literal-CRLF and %0d%0a payloads, the CRLF did not survive and the finding is not validated.
  sources: <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.**  
  `under_review` · score 0.8655 · disproved by: The claim is false if the client used transparently normalises or de-duplicates repeated header fields (many HTTP libraries fold duplicates into a comma list), in which case the injection genuinely occurred but the evidence must come from a raw socket capture or a Wireshark/mitmproxy view rather than the library's parsed headers.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://nodejs.org/api/http.html>

## Fp Rule

- **This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.**  
  `under_review` · score 0.9265 · disproved by: Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no `Set-Cookie` (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **Reject a crlf finding until it is distinguished from the adjacent behaviour this class also covers. "When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious..." and "A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.9205 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A CRLF finding is validated by showing that a line terminator survives" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
- **Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.**  
  `under_review` · score 0.893 · disproved by: The rule is wrong when the reflected value is later re-emitted through a header-emitting API — for example the payload is stored and replayed by a Location or Set-Cookie header, or a downstream proxy/CDN re-serializes the stored value into a response header — in which case the body reflection is the first observable step of real header injection.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://nodejs.org/api/http.html>
- **A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line.**  
  `under_review` · score 0.8655 · disproved by: The rule is wrong when the Location value reaches the wire with a real CR/LF pair split into an additional header line, or when the redirect is emitted by a different component (a proxy, a CDN edge function, a web-server rewrite rule) than the one whose setter the tester assumed was sanitising the value.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.php.net/manual/en/function.header.php>

## Evidence

- **The convincing CRLF evidence is a stored value containing a literal carriage-return/line-feed pair that reappears in a replayed header line, which distinguishes a genuine finding from the far more common case of a header value containing only percent-encoded %0d%0a that the server never decoded.**  
  `under_review` · score 0.893 · disproved by: The claim is false when the application performs a single decode of the stored value immediately before header construction — then a percent-encoded payload in the submitted input still produces literal CRLF on the wire, and the encoded form alone is sufficient evidence provided the decode step is shown.
  sources: <https://nodejs.org/api/http.html> · <https://www.php.net/manual/en/function.header.php>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.**  
  `under_review` · score 0.8655 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (crlf.fp_rule.auto.derived) states the full boundary.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
- **A convincing observation for this class is: The separating observation is WHERE in the response those bytes are.**  
  `under_review` · score 0.8355 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (crlf.fp.percent-encoded-crlf-reflected-in-body) states the full boundary.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Bypass

- **A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.**  
  `high_confidence` · score 0.954 · disproved by: Disproof is a uniform rejection: literal CRLF, %0d%0a, %0a, %0d and %250d%250a all produce the same control response - one header block, no injected header, unchanged body. If the endpoint normalizes or rejects after decoding rather than only before, the bypass is closed and this claim is false. Equivalently, if the injected header only appears in a downstream component the attacker cannot reach, the practical bypass does not exist.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>
- **Modern language-level header setters defeat naive CRLF payloads without any application sanitiser, because a value containing CR or LF raises a TypeError instead of being serialised, so a payload that is not percent-decoded twice and not split-and-rejoined before reaching the setter cannot inject a header.**  
  `high_confidence` · score 0.893 · disproved by: The rule is wrong when the value is passed through a path that bypasses the guarded setter — a raw write to the socket, a C library or framework API that takes a pre-built header block, a template or config file that emits headers, or a reverse proxy that re-serialises a stored value — because those paths re-introduce the injection the TypeError was meant to prevent.
  sources: <https://nodejs.org/api/http.html> · <https://www.php.net/manual/en/function.header.php>

## Chain Link

- **A CRLF defect in a response emitted onto a REUSED connection chains into injecting headers and a URL into a SUBSEQUENT, unrelated request, so the victim of the injected header is not the attacker.**  
  `high_confidence` · score 0.9565 · disproved by: Disproof is any one of: the connection is not reused (each response carries `Connection: close`, so there is no second request to poison); the injected header does not appear on the subsequent request as observed at the origin; or the framing mismatch is corrected before the response is emitted, so request 2 is parsed cleanly. A pipelined two-request test in which request 2 arrives at the origin with only its own headers and its own URL disproves the chain.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **A CRLF defect in a response emitted onto a REUSED connection chains into injecting headers and a URL into a SUBSEQUENT, unrelated request, so the victim of the injected header is not the attacker.**  
  `high_confidence` · score 0.9205 · disproved by: Disproof is any one of: the connection is not reused (each response carries Connection: close, so there is no second request to poison); the injected header does not appear on the subsequent request as observed at the origin; or the framing mismatch is corrected before the response is emitted, so request 2 is parsed cleanly. A pipelined two-request test in which request 2 arrives at the origin with only its own headers and its own URL disproves the chain.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Known gaps

Not yet satisfied: `fp_rules`
