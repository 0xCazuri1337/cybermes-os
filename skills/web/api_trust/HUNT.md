# HUNT runbook — api_trust

**9 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py api_trust web`).

Sources of steps: 0 item-authored, 9 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [api_trust.test.unauthenticated_backend_callback_requires_a_non_public_upstream_address_reachable_by_the_server_and_nothing_else](#api-trust-test-unauthenticated-backend-callback-requires-a-non-public-upstream-address-reachable-by-the-server-and-nothing-else) — Blind / out-of-band confirmation
- [api_trust.test.service_credential_on_a_user_scoped_path_requires_user_scoped_data_with_no_user_principal_in_the_token](#api-trust-test-service-credential-on-a-user-scoped-path-requires-user-scoped-data-with-no-user-principal-in-the-token) — Filesystem sink confirmation
- [api_trust.test.forwarded_header_trust_requires_the_header_changing_the_server_decision_not_just_the_response](#api-trust-test-forwarded-header-trust-requires-the-header-changing-the-server-decision-not-just-the-response) — Filter-bypass ladder
- [api_trust.technique.audience_bound_token_replayed_on_sibling_api](#api-trust-technique-audience-bound-token-replayed-on-sibling-api) — Claim verification (no mechanical template matched)
- [api_trust.signal.scope_bound_grant_absent_means_any_client_can_reach_api](#api-trust-signal-scope-bound-grant-absent-means-any-client-can-reach-api) — Filesystem sink confirmation
- [api_trust.auto.t.60417e2e](#api-trust-auto-t-60417e2e) — Filesystem sink confirmation
- [api_trust.auto.t.179c89a0](#api-trust-auto-t-179c89a0) — Race / TOCTOU attempt
- [api_trust.auto.t.bf3baa1c](#api-trust-auto-t-bf3baa1c) — Filesystem sink confirmation
- [api_trust.auto.t.bf09b373](#api-trust-auto-t-bf09b373) — Filesystem sink confirmation

<a id="api-trust-test-unauthenticated-backend-callback-requires-a-non-public-upstream-address-reachable-by-the-server-and-nothing-else"></a>

## api_trust.test.unauthenticated_backend_callback_requires_a_non_public_upstream_address_reachable_by_the_server_and_nothing_else

**Claim.** A backend trusts an unreachable caller when the server itself will issue a request to an attacker-chosen address that a public client cannot reach, proven by the server's own outbound fetch succeeding where a direct client request to the same address times out.

**Procedure — Blind / out-of-band confirmation** (shapes: blind_confirmation; steps from template)

1. Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.
2. Then test the vulnerable condition. Absence of a callback is only meaningful once the channel is proven.
3. Record the callback evidence (resolved host, token, timestamp) — a blind result with no artefact is not reportable.

**Record:** channel self-test, callback artefact, timing

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="api-trust-test-service-credential-on-a-user-scoped-path-requires-user-scoped-data-with-no-user-principal-in-the-token"></a>

## api_trust.test.service_credential_on_a_user_scoped_path_requires_user_scoped_data_with_no_user_principal_in_the_token

**Claim.** A machine credential has crossed a user-scoped boundary only when a token carrying a client-credentials grant with no user principal is accepted by a user endpoint and returns data scoped to a specific human principal - a name, an email, an order list, an owner id - rather than a generic service view.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="api-trust-test-forwarded-header-trust-requires-the-header-changing-the-server-decision-not-just-the-response"></a>

## api_trust.test.forwarded_header_trust_requires_the_header_changing_the_server_decision_not_just_the_response

**Claim.** Trusting a client-supplied forwarding header is proved when X-Forwarded-For or X-Forwarded-Host changes the server's authorization or routing decision - a 403 becomes a 200, an IP allowlist admits a value the tester supplied, or a generated URL host changes - and not when the header is merely echoed or reflected into a response body.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, encoding_ladder, blind_confirmation; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Encoding / normalisation ladder* — Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="api-trust-technique-audience-bound-token-replayed-on-sibling-api"></a>

## api_trust.technique.audience_bound_token_replayed_on_sibling_api

**Claim.** An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="api-trust-signal-scope-bound-grant-absent-means-any-client-can-reach-api"></a>

## api_trust.signal.scope_bound_grant_absent_means_any_client_can_reach_api

**Claim.** An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never approved.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

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

<a id="api-trust-auto-t-60417e2e"></a>

## api_trust.auto.t.60417e2e

**Claim.** First, test the \whoami endpoint, which requires authorization: Select + in the Postman workbench to open a new request tab.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — body_form: **do** send it as a form field; **observe** framework parsing vs raw body.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the body_form? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="api-trust-auto-t-179c89a0"></a>

## api_trust.auto.t.179c89a0

**Claim.** Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps.

**Procedure — Race / TOCTOU attempt** (shapes: race_condition; steps from template)

1. Identify the check and the use as TWO separate operations, and measure the gap between them.
2. Fire many parallel attempts (tens to hundreds) so at least one lands inside the window.
3. Vary ONLY the timing; the payload and session stay fixed.
4. Report a rate, not a single success: N successes in M attempts both proves the window and tells the reader whether it is practical to exploit.

**Record:** attempts, successes, success rate, window size if measurable

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="api-trust-auto-t-bf3baa1c"></a>

## api_trust.auto.t.bf3baa1c

**Claim.** Now test the hello endpoint that doesn't require authorization: Select + in the Postman workbench to open a new request tab.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="api-trust-auto-t-bf09b373"></a>

## api_trust.auto.t.bf09b373

**Claim.** When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, race_condition; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Race / TOCTOU attempt* — Identify the check and the use as TWO separate operations, and measure the gap between them.
