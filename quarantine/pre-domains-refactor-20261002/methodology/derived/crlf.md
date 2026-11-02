# Methodology — CRLF / Header Injection

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class crlf --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** User input reaches a header or line boundary the protocol treats as a delimiter.

**References.** CWE-93 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**CRLF/response-splitting requires an untrusted value to reach a response header value or a response body position where the HTTP serializer emits a line terminator.**

Map it first: for each candidate endpoint, find the parameter that ends up in a `Location`, `Set-Cookie`, `Refresh`, `X-` custom, or `Content-Type` header, or that is concatenated ahead of a body. Cloudflare's Pingora disclosure is the canonical shape of the outcome: a smuggled request could inject headers and its URL into a subsequent valid request on the same connection, i.e. attacker bytes became response header lines rather than header values. GitHub Security Lab's encoding writeup supplies the defensive half: unexpected newline characters may be introduced specifically to bypass brittle validation, so normalize or encode input so it represents a single line BEFORE validating. Hunting procedure: `GET /redirect?next=<payload>` and `GET /download?fn=<payload>` with a valid session, then read the FULL raw response including every header line and the blank line before the body. If no untrusted value reaches a header or a body-prefix position, the class does not apply to that endpoint.

- *Disproof:* If code review plus observation shows every attacker-influenced value is either (a) never written to a response header, or (b) passed through a CRLF-stripping encoder before the serializer runs, then no attacker byte can reach a line-terminator position and the claim is false. Concretely: a payload of `%0d%0aX-Injected:%20yes` sent to every such parameter returns a response with no `X-Injected` header and no second header block, on every parameter tested.
- *Evidence:* high_confidence — [blog.cloudflare.com](https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora); [github.blog](https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**The signal for CRLF is a differential: a raw CR/LF and its percent-encoded %0d%0a form produce different header structure, and only one of them is rejected.**

Send the same logical payload three ways to the same parameter and diff the RAW response: (1) literal CRLF using curl's `--data-binary` with an actual 0x0d 0x0a, (2) `%0d%0a` percent-encoded, (3) a single encoded `%0a` and separately `%0d`. Read the status line, the full header block, the terminating blank line, and the first body bytes. Interpret: if (2) yields an extra header or a truncated body while (1) is rejected or neutralised, the filter sees the literal control characters but not the encoded form, which is the classic bypass. If both are neutralised the endpoint is filtering. If (1) splits and (2) does not, the filter is decoding. Google's webmaster security guidance frames why percent-encoding is the interesting case: a URL that looks harmless is not, because decoding the percent-encoded characters yields the live payload. GitHub's encoding writeup gives the fix shape: use single-line anchors in the validation regex, which only works if you normalized first.

- *Disproof:* If raw CRLF, %0d%0a, %0a and %0d all produce byte-identical header structure and identical body framing on every response, there is no differential and therefore no signal. One clean way to disprove: a single request with `%0d%0aX-Injected: yes` returns exactly one header block, no `X-Injected`, and the same body as the control request with `x` in that position.
- *Evidence:* high_confidence — [github.blog](https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/); [security.googleblog.com](https://security.googleblog.com/2011/05/website-security-for-webmasters.html)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Response splitting succeeds when attacker bytes are emitted as a new header line inside a response whose Content-Type and framing still let a second header block or injected header be honoured.**

Craft: `GET /go?u=x HTTP/1.1` with a parameter that lands in `Location`, and payload `x%0d%0aSet-Cookie:%20pwn=1%0d%0a%0d%0a<script>alert(1)</script>`. Read the raw response as bytes, not through a client library that normalises headers. A genuine split shows TWO header blocks: the original response ends at the injected blank line and a complete second response follows, or at minimum an injected header line appears before the real blank line. GitHub's post-CSP writeup supplies a real captured instance of exactly this byte pattern - a request URL in which every CRLF is percent-encoded, `%0D%0A`, threading an injected `</textarea>`, an injected `<form action="/logout">` and a hidden `authenticity_token` field between them. CrowdStrike's rootkit writeup shows why the framing side matters: the injector only proceeds when the response Content-Type and the attacker-specified Content-Type match, and it handles both chunked Transfer-Encoding and gzip Content-Encoding, so a split must be judged against the encoded body too. Test the chunked and gzip variants separately; a split that only reproduces with Content-Encoding: gzip is still a split.

- *Disproof:* If the raw response contains exactly one header block, ends at a single blank line, contains no injected header, and has a body identical to the control request's body, response splitting did not occur. Repeat for the raw-CRLF, %0d%0a, chunked and gzip variants; if all four come back structurally identical with no injected header, the claim is false for that endpoint.
- *Evidence:* high_confidence — [crowdstrike.com](https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/); [github.blog](https://github.blog/engineering/platform-security/githubs-post-csp-journey/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.**

Two-part validation. Part one, survival: replay the payload and assert on raw bytes that a second header line or a second header block exists. Assert on the bytes; a client library that raises on a malformed response is itself evidence, not a reason to discard the result. Part two, framing. Re-run the same payload with `Accept-Encoding: gzip` and separately with a chunked request, and inspect the decoded body. CrowdStrike's rootkit analysis is the reference for why framing must be checked explicitly: the injector handles both chunked Transfer-Encoding and gzip Content-Encoding, so the same injected bytes can be invisible in a decoded view and present on the wire. GitHub's encoding writeup supplies the control-side assertion: validation must use single-line anchors, which is only meaningful if the input was normalized or encoded to a single line first, and encoding adds real friction. A finding that only reproduces in one framing mode is still a finding - record which mode, because that is what tells the defender where the fix belongs.

- *Disproof:* Disproof is a raw response in which the line terminator never appears: one header block, one blank line, no injected header, and a body whose decoded content equals the control response's decoded body. If that holds across identity, gzip and chunked framings for both the literal-CRLF and %0d%0a payloads, the CRLF did not survive and the finding is not validated.
- *Evidence:* high_confidence — [crowdstrike.com](https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/); [github.blog](https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.**

The false positive: a scanner sends `?q=%0d%0aSet-Cookie:%20pwn=1`, gets back a page containing the literal string `Set-Cookie: pwn=1` in the HTML, and reports response splitting. The separating observation is WHERE in the response those bytes are. If they appear in the body - after the terminating blank line - the browser's HTML parser treats them as text or as an attribute, not as a header, and no cookie is set. CRLF injection requires the terminator to be honoured by the HTTP message serializer, i.e. to land inside a header value or at a position the serializer writes unescaped, BEFORE the blank line. Google's guidance is the canonical illustration of why the encoded form is worth chasing but not worth reporting on sight: a URL that looks harmless becomes live once the percent-encoded characters are decoded - into HTML in that example, which is a body-context bug, not a header-context one. CrowdStrike's rootkit analysis supplies the positive test: real response injection requires the response Content-Type and the attacker's specified Content-Type to match before injection proceeds. So: parse the raw response into status line, header block, blank line, body. Only a match in the header block, or an extra header block, is a finding.

- *Disproof:* Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no `Set-Cookie` (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.
- *Evidence:* high_confidence — [crowdstrike.com](https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/); [security.googleblog.com](https://security.googleblog.com/2011/05/website-security-for-webmasters.html)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.**

The bypass is a decode-order defect, not a filter weakness. Step 1: the application validates the raw string with a single-line anchored pattern, so `%0d%0a` contains no control byte and passes - GitHub Security Lab's encoding writeup names this exact shape, noting unexpected newline characters may be introduced to bypass brittle validation and that the fix is to normalize or encode the input to a single line BEFORE validating, with single-line anchors in the regex. Step 2: something downstream - a router, a redirect helper, a framework's header writer, a proxy - percent-decodes before the value reaches the HTTP serializer. Step 3: the serializer now sees a real 0x0d 0x0a in a header value and emits a header line break. Hunt it with a three-way differential on the same parameter: literal CRLF, %0d%0a, and %250d%250a (double-encoded). The double-encoded case is the discriminator - if the validator rejects literal, accepts %0d%0a and produces an injected header, and accepts %250d%250a which a second decode turns into the same injected header, the decode order is the bug. Chain it: the same defect in a `Location` or `Set-Cookie` value is what turns a validation gap into response splitting, and a split in front of a shared cache is what turns it into cache poisoning.

- *Disproof:* Disproof is a uniform rejection: literal CRLF, %0d%0a, %0a, %0d and %250d%250a all produce the same control response - one header block, no injected header, unchanged body. If the endpoint normalizes or rejects after decoding rather than only before, the bypass is closed and this claim is false. Equivalently, if the injected header only appears in a downstream component the attacker cannot reach, the practical bypass does not exist.
- *Evidence:* high_confidence — [github.blog](https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/); [security.googleblog.com](https://security.googleblog.com/2011/05/website-security-for-webmasters.html)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A CRLF defect in a response emitted onto a REUSED connection chains into injecting headers and a URL into a SUBSEQUENT, unrelated request, so the victim of the injected header is not the attacker.**

The chain has three links and each is independently observable. Link 1, the split: attacker bytes become a header line in a response on a keep-alive connection. Link 2, the desync: the next request on that connection is parsed as starting mid-response, so the attacker's bytes are prepended to it. Cloudflare's Pingora writeup is the reference for the whole chain, stating that the smuggled request could inject headers and its URL into a subsequent valid request sent on the same connection. Link 3, the impact on a third party: their writeup also shows the resulting response being a 301 with a Location to the attacker's host, followed by the client browser following the redirect and sending a Referrer header indicating which URL was originally visited - so a victim's browsing is disclosed to the attacker without the victim ever interacting. CrowdStrike's rootkit analysis supplies the framing precondition: injected content is only recognised when the response Content-Type matches the attacker-specified Content-Type, and both chunked Transfer-Encoding and gzip Content-Encoding are handled, so test the chain under each framing. Hunt with a two-request pipelined test on one connection and assert that request 2 reaches the origin with the attacker's header on it.

- *Disproof:* Disproof is any one of: the connection is not reused (each response carries `Connection: close`, so there is no second request to poison); the injected header does not appear on the subsequent request as observed at the origin; or the framing mismatch is corrected before the response is emitted, so request 2 is parsed cleanly. A pipelined two-request test in which request 2 arrives at the origin with only its own headers and its own URL disproves the chain.
- *Evidence:* high_confidence — [blog.cloudflare.com](https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora); [crowdstrike.com](https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
