# HUNT runbook — rate_limit

**8 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py rate_limit web`).

Sources of steps: 0 item-authored, 8 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [rate_limit.w11.technique.1f6ec4b0](#rate-limit-w11-technique-1f6ec4b0) — Claim verification (no mechanical template matched)
- [rate_limit.w11.technique.c42b7f18](#rate-limit-w11-technique-c42b7f18) — Filesystem sink confirmation
- [rate_limit.w11.signal.a7c31e94](#rate-limit-w11-signal-a7c31e94) — State-changing verification
- [rate_limit.w11.technique.5d09ab63](#rate-limit-w11-technique-5d09ab63) — Filesystem sink confirmation
- [rate_limit.w11.technique.3b7ae590](#rate-limit-w11-technique-3b7ae590) — Filesystem sink confirmation
- [rate_limit.w11.technique.9a52c7d6](#rate-limit-w11-technique-9a52c7d6) — Filesystem sink confirmation
- [rate_limit.w11.signal.b83d5a27](#rate-limit-w11-signal-b83d5a27) — Filesystem sink confirmation
- [rate_limit.w11.signal.e4071b85](#rate-limit-w11-signal-e4071b85) — Claim verification (no mechanical template matched)

<a id="rate-limit-w11-technique-1f6ec4b0"></a>

## rate_limit.w11.technique.1f6ec4b0

**Claim.** A server that allocates a reusable resource per actor with no intended restriction on the size or number of allocations is unbounded resource consumption, and it is exploitable with plain repeated requests rather than with any credential guess at all.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="rate-limit-w11-technique-c42b7f18"></a>

## rate_limit.w11.technique.c42b7f18

**Claim.** An account lockout that disables the account for a long or permanent period after the failure threshold converts password guessing into a denial of service, because the lockout primitive is reachable by anyone who knows the username.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="rate-limit-w11-signal-a7c31e94"></a>

## rate_limit.w11.signal.a7c31e94

**Claim.** A failure counter keyed on the source IP address instead of on the account is bypassable by a spray: an attacker rotating source addresses never trips any one counter, which is why the counter must be associated with the account.

**Procedure — State-changing verification** (shapes: state_change; steps from template)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="rate-limit-w11-technique-5d09ab63"></a>

## rate_limit.w11.technique.5d09ab63

**Claim.** The correct server-side signal for a client that exceeded its budget is a 429 response whose representation explains the condition and may carry Retry-After, so a handler that answers with 200, or omits the explanation, gives a client no way to back off.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="rate-limit-w11-technique-3b7ae590"></a>

## rate_limit.w11.technique.3b7ae590

**Claim.** Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *State-changing verification* — Capture the pre-state with a read-only request and record it.

<a id="rate-limit-w11-technique-9a52c7d6"></a>

## rate_limit.w11.technique.9a52c7d6

**Claim.** Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and correctly tuned.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="rate-limit-w11-signal-b83d5a27"></a>

## rate_limit.w11.signal.b83d5a27

**Claim.** A limit that is set too generously does not fail closed: once the configured request limit is reached the server begins offloading or queueing new requests, and at peak rates the queue itself overflows and requests are discarded, so the value of the limit is the availability control.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *State-changing verification* — Capture the pre-state with a read-only request and record it.

<a id="rate-limit-w11-signal-e4071b85"></a>

## rate_limit.w11.signal.e4071b85

**Claim.** A high volume of failed logon attempts followed by a single success from the same user, host or timeframe is the log signature that separates throttled spraying from a user's own typo, and it is only visible if authentication failures are logged at all.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.
- **What must be TRUE server-side for this to bite?** — warm: **do** repeat after a success; **observe** behaviour once a cached/derived artefact exists.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
