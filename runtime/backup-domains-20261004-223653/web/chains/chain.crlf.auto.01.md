# crlf: observe, exercise, confirm

> goal: `Establish, exercise and confirm a crlf condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for crlf. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a crlf condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The bypass is a decode-order defect, not a filter weakness. Step 1: the application validates the raw string with a single-line anchored pattern, so `%0d%0a` contains no control byte and passes...

**Requires:** an authorised target with a reachable surface for crlf, and permission to record responses

**Backed by:** `crlf.bypass.percent-encoded-newline-defeats-single-line-anchor`

**This step fails if:** Disproof is a uniform rejection: literal CRLF, %0d%0a, %0a, %0d and %250d%250a all produce the same control response - one header block, no injected header, unchanged body. If the endpoint normalizes or rejects after decoding rather than only before, the bypass is closed and this claim is false. Equivalently, if the injected header only appears in a downstream component the attacker cannot reach, the practical bypass does not exist.

### 2. Exercise it against the target and capture the raw request and response: A CRLF defect in a response emitted onto a REUSED connection chains into injecting headers and a URL into a SUBSEQUENT, unrelated request, so the victim of the injected header is not the attacker.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `crlf.chain_link.split-response-to-cross-request-header-injection`

**This step fails if:** Disproof is any one of: the connection is not reused (each response carries `Connection: close`, so there is no second request to poison); the injected header does not appear on the subsequent request as observed at the origin; or the framing mismatch is corrected before the response is emitted, so request 2 is parsed cleanly. A pipelined two-request test in which request 2 arrives at the origin with only its own headers and its own URL disproves the chain.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `crlf.fp.percent-encoded-crlf-reflected-in-body`

**This step fails if:** Disproof is positional and byte-exact: the injected string occurs only after the single blank line that terminates the header block, the response has exactly one header block, no `Set-Cookie` (or other injected header) appears in the header block, and a cookie jar from a real client run shows no new cookie. If all four hold, the payload was reflected as body text and this is not CRLF injection.
