# CRLF / Header Injection

> surface: `web` · CWE: 93 · OWASP: A03:2021
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

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
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When the client browser followed the redirect, it would trigger this attack by sending a r".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access.**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When the client browser followed the redirect, it would trigger this attack by sending a r".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This component was vulnerable to this request smuggling attack, which could enable modifyi".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The smuggled request in the example above would be sent to the correct origin IP address p".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **This component was vulnerable to this request smuggling attack, which could enable modifying request headers and/or URL sent to customer origins.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This component was vulnerable to this request smuggling attack, which could enable modifyi".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **The smuggled request in the example above would be sent to the correct origin IP address per customer configuration, but some origin servers would respond to the rewritten attacker Host header with a 301 redirect.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The smuggled request in the example above would be sent to the correct origin IP address p".
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Validation

- **A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.**  
  `high_confidence` · score 0.929 · disproved by: Disproof is a raw response in which the line terminator never appears: one header block, one blank line, no injected header, and a body whose decoded content equals the control response's decoded body. If that holds across identity, gzip and chunked framings for both the literal-CRLF and %0d%0a payloads, the CRLF did not survive and the finding is not validated.
  sources: <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Fp Rule

- **This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.**  
  `high_confidence` · score 0.9265 · disproved by: Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no `Set-Cookie` (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **Reject a crlf finding until it is distinguished from the adjacent behaviour this class also covers. "When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious..." and "A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.9205 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A CRLF finding is validated by showing that a line terminator survives" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>

## Bypass

- **A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.**  
  `high_confidence` · score 0.954 · disproved by: Disproof is a uniform rejection: literal CRLF, %0d%0a, %0a, %0d and %250d%250a all produce the same control response - one header block, no injected header, unchanged body. If the endpoint normalizes or rejects after decoding rather than only before, the bypass is closed and this claim is false. Equivalently, if the injected header only appears in a downstream component the attacker cannot reach, the practical bypass does not exist.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>

## Chain Link

- **A CRLF defect in a response emitted onto a REUSED connection chains into injecting headers and a URL into a SUBSEQUENT, unrelated request, so the victim of the injected header is not the attacker.**  
  `high_confidence` · score 0.9565 · disproved by: Disproof is any one of: the connection is not reused (each response carries `Connection: close`, so there is no second request to poison); the injected header does not appear on the subsequent request as observed at the origin; or the framing mismatch is corrected before the response is emitted, so request 2 is parsed cleanly. A pipelined two-request test in which request 2 arrives at the origin with only its own headers and its own URL disproves the chain.
  sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
