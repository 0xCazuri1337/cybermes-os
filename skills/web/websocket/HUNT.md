# HUNT runbook — websocket

**13 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py websocket web`).

Sources of steps: 0 item-authored, 13 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [websocket.bypass.query_string_token_survives_log_and_proxy](#websocket-bypass-query-string-token-survives-log-and-proxy) — Single-parameter differential probe
- [websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes](#websocket-bypass-proxy-reachable-websocket-endpoints-need-the-same-auth-as-http-routes) — Filesystem sink confirmation
- [websocket.test.a_reverse_proxy_that_routes_http_endpoints_throu](#websocket-test-a-reverse-proxy-that-routes-http-endpoints-throu) — Claim verification (no mechanical template matched)
- [websocket.technique.jwt_subprotocol_or_post_connect_frame_as_auth_channel](#websocket-technique-jwt-subprotocol-or-post-connect-frame-as-auth-channel) — Claim verification (no mechanical template matched)
- [websocket.validation.ids_only_channel_proves_no_data_exposure](#websocket-validation-ids-only-channel-proves-no-data-exposure) — Encoding / normalisation ladder
- [websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade](#websocket-validation-prove-cross-site-reach-with-a-foreign-origin-upgrade) — Claim verification (no mechanical template matched)
- [websocket.test.a_websocket_handshake_is_a_normal_http_upgrade_r](#websocket-test-a-websocket-handshake-is-a-normal-http-upgrade-r) — Claim verification (no mechanical template matched)
- [websocket.test.a_page_or_config_string_containing_wss_is_not_by](#websocket-test-a-page-or-config-string-containing-wss-is-not-by) — Claim verification (no mechanical template matched)
- [websocket.test.receiving_messages_injected_into_a_websocket_cha](#websocket-test-receiving-messages-injected-into-a-websocket-cha) — Claim verification (no mechanical template matched)
- [websocket.test.the_convincing_evidence_for_cross_site_websocket](#websocket-test-the-convincing-evidence-for-cross-site-websocket) — Claim verification (no mechanical template matched)
- [websocket.auto.t.2b51e8f4](#websocket-auto-t-2b51e8f4) — Claim verification (no mechanical template matched)
- [websocket.auto.01](#websocket-auto-01) — Filesystem sink confirmation
- [websocket.auto.t.56463cf6](#websocket-auto-t-56463cf6) — Filesystem sink confirmation

<a id="websocket-bypass-query-string-token-survives-log-and-proxy"></a>

## websocket.bypass.query_string_token_survives_log_and_proxy

**Claim.** Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-bypass-proxy-reachable-websocket-endpoints-need-the-same-auth-as-http-routes"></a>

## websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes

**Claim.** A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-test-a-reverse-proxy-that-routes-http-endpoints-throu"></a>

## websocket.test.a_reverse_proxy_that_routes_http_endpoints_throu

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-technique-jwt-subprotocol-or-post-connect-frame-as-auth-channel"></a>

## websocket.technique.jwt_subprotocol_or_post_connect_frame_as_auth_channel

**Claim.** Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-validation-ids-only-channel-proves-no-data-exposure"></a>

## websocket.validation.ids_only_channel_proves_no_data_exposure

**Claim.** A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-validation-prove-cross-site-reach-with-a-foreign-origin-upgrade"></a>

## websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade

**Claim.** The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-test-a-websocket-handshake-is-a-normal-http-upgrade-r"></a>

## websocket.test.a_websocket_handshake_is_a_normal_http_upgrade_r

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-test-a-page-or-config-string-containing-wss-is-not-by"></a>

## websocket.test.a_page_or_config_string_containing_wss_is_not_by

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

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

<a id="websocket-test-receiving-messages-injected-into-a-websocket-cha"></a>

## websocket.test.receiving_messages_injected_into_a_websocket_cha

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-test-the-convincing-evidence-for-cross-site-websocket"></a>

## websocket.test.the_convincing_evidence_for_cross_site_websocket

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

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

<a id="websocket-auto-t-2b51e8f4"></a>

## websocket.auto.t.2b51e8f4

**Claim.** Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-auto-01"></a>

## websocket.auto.01

**Claim.** Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="websocket-auto-t-56463cf6"></a>

## websocket.auto.t.56463cf6

**Claim.** Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
