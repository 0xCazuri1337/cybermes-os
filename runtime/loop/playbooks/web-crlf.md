# Hunt card — crlf

10 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## crlf.signal.encoded-vs-raw-newline-differential

**Claim.** The signal for CRLF is a differential: a raw CR/LF and its percent-encoded %0d%0a form produce different header structure, and only one of them is rejected.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.bypass.percent-encoded-newline-defeats-single-line-anchor

**Claim.** A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.

**Procedure — item-authored procedure** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Something downstream - a router, a redirect helper, a framework's header writer, a proxy - percent-decodes before the value reaches the HTTP serializer.
2. The serializer now sees a real 0x0d 0x0a in a header value and emits a header line break.

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.technique.response-splitting-header-injection

**Claim.** Response splitting succeeds when attacker bytes are emitted as a new header line inside a response whose Content-Type and framing still let a second header block or injected header be honoured.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.validation.newline-normalization-and-framing-differential

**Claim.** A CRLF finding is validated by showing that a line terminator survives into the emitted response, and that the response's body framing (identity, chunked, gzip) does not neutralise the injected boundary.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.bypass.a_language_level_header_api_that_sanitizes_defeats_the_injection_before_the_wire

**Claim.** Modern language-level header setters defeat naive CRLF payloads without any application sanitiser, because a value containing CR or LF raises a TypeError instead of being serialised, so a payload that is not percent-decoded twice and not split-and-rejoined before reaching the setter cannot inject a header.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.test.seeing_a_0d_0a_payload_echoed_back_in_an_html_er

**Claim.** To decide this case, observe: Mechanism: Seeing a %0d%0a payload echoed back in an HTML error page or response body is not CRLF injection: the flaw requires the injected CR and LF to become additional header field lines in the response, which the server's HTTP serializer, not the template engine, controls.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.validation.a_new_response_line_is_proved_by_a_second_header_pair_in_the_raw_response

**Claim.** CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.test.modern_language_level_header_setters_defeat_naiv

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.test.a_3xx_response_whose_location_value_merely_conta

**Claim.** To decide this case, observe: Mechanism: A 3xx response whose Location value merely contains attacker-chosen text or an encoded newline is not CRLF injection: in several mainstream languages setting a Location header automatically produces the redirect status, so the status code is evidence of the redirect and not of an injected header line.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## crlf.test.crlf_injection_is_proved_only_by_the_raw_respons

**Claim.** To decide this case, observe: Mechanism: CRLF injection is proved only by the raw response containing a header block the attacker controls — an extra header line, a truncated earlier header, or a second response head after the injected blank line — visible in a byte-level or non-normalising client view, not by a 200 status with attacker text in it.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions
