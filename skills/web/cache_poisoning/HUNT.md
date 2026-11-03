# HUNT runbook — cache_poisoning

**17 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py cache_poisoning web`).

Sources of steps: 0 item-authored, 17 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [cache_poisoning.validation.replay_and_ttl](#cache-poisoning-validation-replay-and-ttl) — Race / TOCTOU attempt
- [cache_poisoning.test.confirm_poisoning_by_replaying_a_clean_request_f](#cache-poisoning-test-confirm-poisoning-by-replaying-a-clean-request-f) — Claim verification (no mechanical template matched)
- [cache_poisoning.signal.unkeyed_parameter_reflected](#cache-poisoning-signal-unkeyed-parameter-reflected) — Single-parameter differential probe
- [cache_poisoning.test.a_response_that_echoes_an_unkeyed_header_or_para](#cache-poisoning-test-a-response-that-echoes-an-unkeyed-header-or-para) — Single-parameter differential probe
- [cache_poisoning.validation.prove_persistence_by_replaying_a_plain_request_with_no_attacker_markers](#cache-poisoning-validation-prove-persistence-by-replaying-a-plain-request-with-no-attacker-markers) — Filesystem sink confirmation
- [cache_poisoning.bypass.head_requests_are_cached_under_a_get_key_when_head_to_get_conversion_is_on](#cache-poisoning-bypass-head-requests-are-cached-under-a-get-key-when-head-to-get-conversion-is-on) — Filesystem sink confirmation
- [cache_poisoning.auto.05](#cache-poisoning-auto-05) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.t.48732c44](#cache-poisoning-auto-t-48732c44) — Claim verification (no mechanical template matched)
- [cache_poisoning.test.switching_a_route_to_no_store_leaves_already_poisoned_entries_live](#cache-poisoning-test-switching-a-route-to-no-store-leaves-already-poisoned-entries-live) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.01](#cache-poisoning-auto-01) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.02](#cache-poisoning-auto-02) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.04](#cache-poisoning-auto-04) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.t.be57e007](#cache-poisoning-auto-t-be57e007) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.t.ee91dd08](#cache-poisoning-auto-t-ee91dd08) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.t.c59a73fa](#cache-poisoning-auto-t-c59a73fa) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.03](#cache-poisoning-auto-03) — Claim verification (no mechanical template matched)
- [cache_poisoning.auto.t.2a49894a](#cache-poisoning-auto-t-2a49894a) — Claim verification (no mechanical template matched)

<a id="cache-poisoning-validation-replay-and-ttl"></a>

## cache_poisoning.validation.replay_and_ttl

**Claim.** Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.

**Procedure — Race / TOCTOU attempt** (shapes: race_condition; steps from template)

1. Identify the check and the use as TWO separate operations, and measure the gap between them.
2. Fire many parallel attempts (tens to hundreds) so at least one lands inside the window.
3. Vary ONLY the timing; the payload and session stay fixed.
4. Report a rate, not a single success: N successes in M attempts both proves the window and tells the reader whether it is practical to exploit.

**Record:** attempts, successes, success rate, window size if measurable

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-test-confirm-poisoning-by-replaying-a-clean-request-f"></a>

## cache_poisoning.test.confirm_poisoning_by_replaying_a_clean_request_f

**Claim.** To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-signal-unkeyed-parameter-reflected"></a>

## cache_poisoning.signal.unkeyed_parameter_reflected

**Claim.** A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-test-a-response-that-echoes-an-unkeyed-header-or-para"></a>

## cache_poisoning.test.a_response_that_echoes_an_unkeyed_header_or_para

**Claim.** To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-validation-prove-persistence-by-replaying-a-plain-request-with-no-attacker-markers"></a>

## cache_poisoning.validation.prove_persistence_by_replaying_a_plain_request_with_no_attacker_markers

**Claim.** Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-bypass-head-requests-are-cached-under-a-get-key-when-head-to-get-conversion-is-on"></a>

## cache_poisoning.bypass.head_requests_are_cached_under_a_get_key_when_head_to_get_conversion_is_on

**Claim.** When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-05"></a>

## cache_poisoning.auto.05

**Claim.** The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-t-48732c44"></a>

## cache_poisoning.auto.t.48732c44

**Claim.** The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-test-switching-a-route-to-no-store-leaves-already-poisoned-entries-live"></a>

## cache_poisoning.test.switching_a_route_to_no_store_leaves_already_poisoned_entries_live

**Claim.** A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-01"></a>

## cache_poisoning.auto.01

**Claim.** A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-02"></a>

## cache_poisoning.auto.02

**Claim.** When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-04"></a>

## cache_poisoning.auto.04

**Claim.** Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-t-be57e007"></a>

## cache_poisoning.auto.t.be57e007

**Claim.** A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-t-ee91dd08"></a>

## cache_poisoning.auto.t.ee91dd08

**Claim.** When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-t-c59a73fa"></a>

## cache_poisoning.auto.t.c59a73fa

**Claim.** Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-03"></a>

## cache_poisoning.auto.03

**Claim.** If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="cache-poisoning-auto-t-2a49894a"></a>

## cache_poisoning.auto.t.2a49894a

**Claim.** If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
