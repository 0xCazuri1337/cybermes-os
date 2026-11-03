# HUNT runbook — crlf

**12 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py crlf web`).

Sources of steps: 1 item-authored, 11 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [crlf.signal.encoded-vs-raw-newline-differential](#crlf-signal-encoded-vs-raw-newline-differential) — Filter-bypass ladder
- [crlf.bypass.percent-encoded-newline-defeats-single-line-anchor](#crlf-bypass-percent-encoded-newline-defeats-single-line-anchor) — item-authored procedure
- [crlf.technique.response-splitting-header-injection](#crlf-technique-response-splitting-header-injection) — Encoding / normalisation ladder
- [crlf.validation.newline-normalization-and-framing-differential](#crlf-validation-newline-normalization-and-framing-differential) — Encoding / normalisation ladder
- [crlf.bypass.a_language_level_header_api_that_sanitizes_defeats_the_injection_before_the_wire](#crlf-bypass-a-language-level-header-api-that-sanitizes-defeats-the-injection-before-the-wire) — Encoding / normalisation ladder
- [crlf.test.seeing_a_0d_0a_payload_echoed_back_in_an_html_er](#crlf-test-seeing-a-0d-0a-payload-echoed-back-in-an-html-er) — Claim verification (no mechanical template matched)
- [crlf.auto.03](#crlf-auto-03) — Claim verification (no mechanical template matched)
- [crlf.auto.t.33237330](#crlf-auto-t-33237330) — Claim verification (no mechanical template matched)
- [crlf.validation.a_new_response_line_is_proved_by_a_second_header_pair_in_the_raw_response](#crlf-validation-a-new-response-line-is-proved-by-a-second-header-pair-in-the-raw-response) — Claim verification (no mechanical template matched)
- [crlf.test.modern_language_level_header_setters_defeat_naiv](#crlf-test-modern-language-level-header-setters-defeat-naiv) — Claim verification (no mechanical template matched)
- [crlf.test.a_3xx_response_whose_location_value_merely_conta](#crlf-test-a-3xx-response-whose-location-value-merely-conta) — Encoding / normalisation ladder
- [crlf.test.crlf_injection_is_proved_only_by_the_raw_respons](#crlf-test-crlf-injection-is-proved-only-by-the-raw-respons) — Claim verification (no mechanical template matched)

<a id="crlf-signal-encoded-vs-raw-newline-differential"></a>

## crlf.signal.encoded-vs-raw-newline-differential

**Claim.** The signal for CRLF is a differential: a raw CR/LF and its percent-encoded %0d%0a form produce different header structure, and only one of them is rejected.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, encoding_ladder, filesystem_sink; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.
- **WHAT transformation sits between you and the sink?** — url: **do** send it percent-encoded once; **observe** whether the decode happens before or after validation.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

You are at the `url` rung. Continue the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Encoding / normalisation ladder* — Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="crlf-bypass-percent-encoded-newline-defeats-single-line-anchor"></a>

## crlf.bypass.percent-encoded-newline-defeats-single-line-anchor

**Claim.** A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.

**Procedure — item-authored procedure** (shapes: filter_bypass, encoding_ladder; steps from item)

1. Something downstream - a router, a redirect helper, a framework's header writer, a proxy - percent-decodes before the value reaches the HTTP serializer.
2. The serializer now sees a real 0x0d 0x0a in a header value and emits a header line break.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **WHAT transformation sits between you and the sink?** — double: **do** send it percent-encoded twice; **observe** single-decode filters are bypassed.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

You are at the `double` rung. Continue the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Encoding / normalisation ladder* — Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.

<a id="crlf-technique-response-splitting-header-injection"></a>

## crlf.technique.response-splitting-header-injection

**Claim.** Response splitting succeeds when attacker bytes are emitted as a new header line inside a response whose Content-Type and framing still let a second header block or injected header be honoured.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder, filesystem_sink; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **WHAT transformation sits between you and the sink?** — url: **do** send it percent-encoded once; **observe** whether the decode happens before or after validation.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

You are at the `url` rung. Continue the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="crlf-validation-newline-normalization-and-framing-differential"></a>

## crlf.validation.newline-normalization-and-framing-differential

**Claim.** A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="crlf-bypass-a-language-level-header-api-that-sanitizes-defeats-the-injection-before-the-wire"></a>

## crlf.bypass.a_language_level_header_api_that_sanitizes_defeats_the_injection_before_the_wire

**Claim.** Modern language-level header setters defeat naive CRLF payloads without any application sanitiser, because a value containing CR or LF raises a TypeError instead of being serialised, so a payload that is not percent-decoded twice and not split-and-rejoined before reaching the setter cannot inject a header.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder, filesystem_sink; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="crlf-test-seeing-a-0d-0a-payload-echoed-back-in-an-html-er"></a>

## crlf.test.seeing_a_0d_0a_payload_echoed_back_in_an_html_er

**Claim.** To decide this case, observe: Mechanism: Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="crlf-auto-03"></a>

## crlf.auto.03

**Claim.** When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="crlf-auto-t-33237330"></a>

## crlf.auto.t.33237330

**Claim.** When the client browser followed the redirect, it would trigger this attack by sending a request to the attacker hostname, along with a Referrer header indicating which URL was originally visited, making it possible to load a malicious asset and observe what traffic a visitor was trying to access.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="crlf-validation-a-new-response-line-is-proved-by-a-second-header-pair-in-the-raw-response"></a>

## crlf.validation.a_new_response_line_is_proved_by_a_second_header_pair_in_the_raw_response

**Claim.** CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="crlf-test-modern-language-level-header-setters-defeat-naiv"></a>

## crlf.test.modern_language_level_header_setters_defeat_naiv

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

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

<a id="crlf-test-a-3xx-response-whose-location-value-merely-conta"></a>

## crlf.test.a_3xx_response_whose_location_value_merely_conta

**Claim.** To decide this case, observe: Mechanism: A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="crlf-test-crlf-injection-is-proved-only-by-the-raw-respons"></a>

## crlf.test.crlf_injection_is_proved_only_by_the_raw_respons

**Claim.** To decide this case, observe: Mechanism: CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
