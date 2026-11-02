# Hunt card — bizlogic

10 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## bizlogic.technique.negative_value_inverts_business_rule_direction

**Claim.** A numeric business rule validated only as within-an-upper-bound passes for a negative input, so a balance check approves a transfer that moves funds in the opposite direction to the one requested.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.validation.single_use_redemption_sequential_then_parallel

**Claim.** A limit-overrun or single-use business-logic claim is confirmed only when parallel requests to the same single-use endpoint succeed where an identical sequential sequence fails, proving the limit was overrun rather than merely exercised twice.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.test.an_oversized_refund_credit_or_payout_accepted_wi

**Claim.** To decide this case, observe: Discard the report that says the endpoint validates nothing only when you could not establish the intended rule: without a stated cap, a documented maximum, or a control request showing the server enforces one, a large accepted amount proves nothing about a missing check.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.technique.back_navigation_reapplies_single_use_discount

**Claim.** A once-per-transaction limit enforced only in the forward UI flow is bypassed by navigating back to the discount step, because the server-side count is not tied to the transaction.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

## bizlogic.test.a_limit_overrun_or_single_use_business_logic_cla

**Claim.** To decide this case, observe: Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.technique.encryption_oracle_reused_by_another_input

**Claim.** An endpoint that encrypts attacker-controlled input with the server's key and returns the ciphertext becomes an oracle whenever another endpoint accepts ciphertext under the same algorithm.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.test.a_logic_flaw_reported_by_an_automated_scanner_wi

**Claim.** To decide this case, observe: A reportable finding needs three things together: a stated rule the application is supposed to enforce, an observed deviation from it, and a consequence.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.test.a_price_discount_or_total_that_the_server_echoes

**Claim.** To decide this case, observe: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## bizlogic.technique.start_then_abort_workflow_accumulates_persistent_credit

**Claim.** When a workflow grants a durable credit at an intermediate step and does not roll it back on cancellation, an attacker accumulates credit by repeatedly starting a transaction and abandoning it without ever paying.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## bizlogic.technique.email_parser_discrepancy_confers_restricted_domain_access

**Claim.** When the application authorises on the domain extracted from an email address, differing parsers let an address that passes validation be interpreted as a different domain, granting access to the restricted area.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder, filesystem_sink)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence
