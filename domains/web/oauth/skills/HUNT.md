# HUNT runbook — oauth

**17 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py oauth web`).

Sources of steps: 0 item-authored, 17 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [oauth.test.mix_up_requires_an_iss_value_that_differs_from_the_tenant_the_code_is_redeemed_against](#oauth-test-mix-up-requires-an-iss-value-that-differs-from-the-tenant-the-code-is-redeemed-against) — Single-parameter differential probe
- [oauth.test.csrf_on_the_callback_requires_a_state_value_issued_to_a_different_browser_session_being_accepted](#oauth-test-csrf-on-the-callback-requires-a-state-value-issued-to-a-different-browser-session-being-accepted) — Blind / out-of-band confirmation
- [oauth.test.token_audience_confusion_requires_a_token_minted_for_one_api_accepted_by_a_different_api](#oauth-test-token-audience-confusion-requires-a-token-minted-for-one-api-accepted-by-a-different-api) — Encoding / normalisation ladder
- [oauth.signal.hth_authorization_code_grant_get_ca](#oauth-signal-hth-authorization-code-grant-get-ca) — Blind / out-of-band confirmation
- [oauth.signal.authorization_request_params](#oauth-signal-authorization-request-params) — Claim verification (no mechanical template matched)
- [oauth.bypass.an_open_redirector_on_the_callback_host_defeats_a_correct_redirect_uri_check](#oauth-bypass-an-open-redirector-on-the-callback-host-defeats-a-correct-redirect-uri-check) — Filesystem sink confirmation
- [oauth.validation.mix_up_defence_is_only_required_when_a_client_talks_to_two_authorization_servers](#oauth-validation-mix-up-defence-is-only-required-when-a-client-talks-to-two-authorization-servers) — Filesystem sink confirmation
- [oauth.tech.callback_csrf_missing_state](#oauth-tech-callback-csrf-missing-state) — Filter-bypass ladder
- [oauth.validation.scope_escalation_proof](#oauth-validation-scope-escalation-proof) — Claim verification (no mechanical template matched)
- [oauth.signal.hth_get_authorization_client_id_12345](#oauth-signal-hth-get-authorization-client-id-12345) — Claim verification (no mechanical template matched)
- [oauth.bypass.code_interception_mixup_path_traversal](#oauth-bypass-code-interception-mixup-path-traversal) — Filesystem sink confirmation
- [oauth.tech.redirect_uri_manipulation](#oauth-tech-redirect-uri-manipulation) — Single-parameter differential probe
- [oauth.signal.implicit_grant_or_leaked_secret](#oauth-signal-implicit-grant-or-leaked-secret) — Filesystem sink confirmation
- [oauth.signal.hth_the_resulting_get_request_will_con](#oauth-signal-hth-the-resulting-get-request-will-con) — Single-parameter differential probe
- [oauth.tech.scope_escalation](#oauth-tech-scope-escalation) — Filesystem sink confirmation
- [oauth.validation.account_takeover_proof](#oauth-validation-account-takeover-proof) — Claim verification (no mechanical template matched)
- [oauth.technique.hth_security_assertion_markup_language](#oauth-technique-hth-security-assertion-markup-language) — Encoding / normalisation ladder

<a id="oauth-test-mix-up-requires-an-iss-value-that-differs-from-the-tenant-the-code-is-redeemed-against"></a>

## oauth.test.mix_up_requires_an_iss_value_that_differs_from_the_tenant_the_code_is_redeemed_against

**Claim.** A mix-up finding is proved only when the authorization response carries an iss value that is not the issuer of the authorization server the client sent the request to, and the resulting code is then accepted by a token endpoint belonging to that other issuer.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, blind_confirmation; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="oauth-test-csrf-on-the-callback-requires-a-state-value-issued-to-a-different-browser-session-being-accepted"></a>

## oauth.test.csrf_on_the_callback_requires_a_state_value_issued_to_a_different_browser_session_being_accepted

**Claim.** A callback CSRF finding requires replaying an authorization response carrying a state value that the receiving browser session never issued, and observing that the client completes the code exchange and binds the resulting session anyway.

**Procedure — Blind / out-of-band confirmation** (shapes: blind_confirmation; steps from template)

1. Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.
2. Then test the vulnerable condition. Absence of a callback is only meaningful once the channel is proven.
3. Record the callback evidence (resolved host, token, timestamp) — a blind result with no artefact is not reportable.

**Record:** channel self-test, callback artefact, timing

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-test-token-audience-confusion-requires-a-token-minted-for-one-api-accepted-by-a-different-api"></a>

## oauth.test.token_audience_confusion_requires_a_token_minted_for_one_api_accepted_by_a_different_api

**Claim.** Cross-tenant token confusion is proved when a token whose aud names resource A is presented to the resource server for resource B and B returns the protected data instead of rejecting it, which can only happen if B skipped the aud check entirely rather than merely checking it loosely.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder, state_change; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *State-changing verification* — Capture the pre-state with a read-only request and record it.

<a id="oauth-signal-hth-authorization-code-grant-get-ca"></a>

## oauth.signal.hth_authorization_code_grant_get_ca

**Claim.** Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.

**Procedure — Blind / out-of-band confirmation** (shapes: blind_confirmation; steps from template)

1. Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.
2. Then test the vulnerable condition. Absence of a callback is only meaningful once the channel is proven.
3. Record the callback evidence (resolved host, token, timestamp) — a blind result with no artefact is not reportable.

**Record:** channel self-test, callback artefact, timing

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-signal-authorization-request-params"></a>

## oauth.signal.authorization_request_params

**Claim.** The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-bypass-an-open-redirector-on-the-callback-host-defeats-a-correct-redirect-uri-check"></a>

## oauth.bypass.an_open_redirector_on_the_callback_host_defeats_a_correct_redirect_uri_check

**Claim.** The authorization server can enforce exact redirect_uri matching perfectly and still leak the code, because browsers reattach the URL fragment to a Location redirect that contains no fragment of its own.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, blind_confirmation; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="oauth-validation-mix-up-defence-is-only-required-when-a-client-talks-to-two-authorization-servers"></a>

## oauth.validation.mix_up_defence_is_only_required_when_a_client_talks_to_two_authorization_servers

**Claim.** Reporting a missing mix-up defence on a single-issuer client is a false positive, because RFC 9700 states the defence is only required when the client interacts with two or more authorization servers.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-tech-callback-csrf-missing-state"></a>

## oauth.tech.callback_csrf_missing_state

**Claim.** An authorization request with no state/nonce lets an attacker pre-initiate the flow and bind the victim's client-side session to the attacker's AS identity.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, blind_confirmation; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="oauth-validation-scope-escalation-proof"></a>

## oauth.validation.scope_escalation_proof

**Claim.** Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.

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

<a id="oauth-signal-hth-get-authorization-client-id-12345"></a>

## oauth.signal.hth_get_authorization_client_id_12345

**Claim.** A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.

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

<a id="oauth-bypass-code-interception-mixup-path-traversal"></a>

## oauth.bypass.code_interception_mixup_path_traversal

**Claim.** Even strict redirect_uri matching can be bypassed via mix-up attacks, open-redirect chain with fragment reattachment, or trailing path traversal on the callback path.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, blind_confirmation; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="oauth-tech-redirect-uri-manipulation"></a>

## oauth.tech.redirect_uri_manipulation

**Claim.** Redirect URI allowlists are bypassable via prefix/duplicate/localhost tricks, path traversal on the callback path, or a dangling wildcard subdomain.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, blind_confirmation; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="oauth-signal-implicit-grant-or-leaked-secret"></a>

## oauth.signal.implicit_grant_or_leaked_secret

**Claim.** response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.

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

<a id="oauth-signal-hth-the-resulting-get-request-will-con"></a>

## oauth.signal.hth_the_resulting_get_request_will_con

**Claim.** In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-tech-scope-escalation"></a>

## oauth.tech.scope_escalation

**Claim.** Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-validation-account-takeover-proof"></a>

## oauth.validation.account_takeover_proof

**Claim.** Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="oauth-technique-hth-security-assertion-markup-language"></a>

## oauth.technique.hth_security_assertion_markup_language

**Claim.** Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
