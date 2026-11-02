---
name: crlf-hunting
description: Use when hunting CRLF / Header Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# CRLF / Header Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 93 · OWASP A03:2021
> evidence: 7 items, 7 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

User input reaches a header or line boundary the protocol treats as a delimiter.

**Also called:** crlf injection, header injection, response splitting


## Prerequisites (do not start without these)

- CRLF/response-splitting requires an untrusted value to reach a response header value or a response body position where the HTTP serializer emits a line terminator.
  - **Disproof:** If code review plus observation shows every attacker-influenced value is either (a) never written to a response header, or (b) passed through a CRLF-stripping encoder before the serializer runs, then no attacker byte can reach a line-terminator position and the claim is false. Concretely: a payload of `%0d%0aX-Injected:%20yes` sent to every such parameter returns a response with no `X-Injected` header and no second header block, on every parameter tested.
  - Sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>

## Recon signals (where to look)

- The signal for CRLF is a differential: a raw CR/LF and its percent-encoded %0d%0a form produce different header structure, and only one of them is rejected.
  - **Disproof:** If raw CRLF, %0d%0a, %0a and %0d all produce byte-identical header structure and identical body framing on every response, there is no differential and therefore no signal. One clean way to disprove: a single request with `%0d%0aX-Injected: yes` returns exactly one header block, no `X-Injected`, and the same body as the control request with `x` in that position.
  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>

## Techniques (what to change)

- Response splitting succeeds when attacker bytes are emitted as a new header line inside a response whose Content-Type and framing still let a second header block or injected header be honoured.
  - **Disproof:** If the raw response contains exactly one header block, ends at a single blank line, contains no injected header, and has a body identical to the control request's body, response splitting did not occur. Repeat for the raw-CRLF, %0d%0a, chunked and gzip variants; if all four come back structurally identical with no injected header, the claim is false for that endpoint.
  - Sources: <https://github.blog/engineering/platform-security/githubs-post-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Validation bar (how to prove it)

- A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.
  - **Disproof:** Disproof is a raw response in which the line terminator never appears: one header block, one blank line, no injected header, and a body whose decoded content equals the control response's decoded body. If that holds across identity, gzip and chunked framings for both the literal-CRLF and %0d%0a payloads, the CRLF did not survive and the finding is not validated.
  - Sources: <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## False-positive rules (when to reject it)

- This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.
  - **Disproof:** Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no `Set-Cookie` (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.
  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

## Defence bypasses

- A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.
  - **Disproof:** Disproof is a uniform rejection: literal CRLF, %0d%0a, %0a, %0d and %250d%250a all produce the same control response - one header block, no injected header, unchanged body. If the endpoint normalizes or rejects after decoding rather than only before, the bypass is closed and this claim is false. Equivalently, if the injected header only appears in a downstream component the attacker cannot reach, the practical bypass does not exist.
  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/>

## Chaining opportunities

- A CRLF defect in a response emitted onto a REUSED connection chains into injecting headers and a URL into a SUBSEQUENT, unrelated request, so the victim of the injected header is not the attacker.
  - **Disproof:** Disproof is any one of: the connection is not reused (each response carries `Connection: close`, so there is no second request to poison); the injected header does not appear on the subsequent request as observed at the origin; or the framing mismatch is corrected before the response is emitted, so request 2 is parsed cleanly. A pipelined two-request test in which request 2 arrives at the origin with only its own headers and its own URL disproves the chain.
  - Sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>

---
Full class document: `skills/Web/crlf/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id crlf`
