# HUNT runbook — bizlogic

**13 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py bizlogic web`).

Sources of steps: 0 item-authored, 13 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [bizlogic.technique.negative_value_inverts_business_rule_direction](#bizlogic-technique-negative-value-inverts-business-rule-direction) — Claim verification (no mechanical template matched)
- [bizlogic.validation.single_use_redemption_sequential_then_parallel](#bizlogic-validation-single-use-redemption-sequential-then-parallel) — Filesystem sink confirmation
- [bizlogic.test.an_oversized_refund_credit_or_payout_accepted_wi](#bizlogic-test-an-oversized-refund-credit-or-payout-accepted-wi) — Claim verification (no mechanical template matched)
- [bizlogic.technique.back_navigation_reapplies_single_use_discount](#bizlogic-technique-back-navigation-reapplies-single-use-discount) — Claim verification (no mechanical template matched)
- [bizlogic.test.a_limit_overrun_or_single_use_business_logic_cla](#bizlogic-test-a-limit-overrun-or-single-use-business-logic-cla) — Claim verification (no mechanical template matched)
- [bizlogic.technique.encryption_oracle_reused_by_another_input](#bizlogic-technique-encryption-oracle-reused-by-another-input) — Single-parameter differential probe
- [bizlogic.test.a_logic_flaw_reported_by_an_automated_scanner_wi](#bizlogic-test-a-logic-flaw-reported-by-an-automated-scanner-wi) — Claim verification (no mechanical template matched)
- [bizlogic.test.a_price_discount_or_total_that_the_server_echoes](#bizlogic-test-a-price-discount-or-total-that-the-server-echoes) — Encoding / normalisation ladder
- [bizlogic.technique.start_then_abort_workflow_accumulates_persistent_credit](#bizlogic-technique-start-then-abort-workflow-accumulates-persistent-credit) — Filesystem sink confirmation
- [bizlogic.technique.email_parser_discrepancy_confers_restricted_domain_access](#bizlogic-technique-email-parser-discrepancy-confers-restricted-domain-access) — Encoding / normalisation ladder
- [bizlogic.auto.01](#bizlogic-auto-01) — Claim verification (no mechanical template matched)
- [bizlogic.auto.02](#bizlogic-auto-02) — Claim verification (no mechanical template matched)
- [bizlogic.auto.03](#bizlogic-auto-03) — Claim verification (no mechanical template matched)

<a id="bizlogic-technique-negative-value-inverts-business-rule-direction"></a>

## bizlogic.technique.negative_value_inverts_business_rule_direction

**Claim.** A numeric business rule validated only as within-an-upper-bound passes for a negative input, so a balance check approves a transfer that moves funds in the opposite direction to the one requested.

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

<a id="bizlogic-validation-single-use-redemption-sequential-then-parallel"></a>

## bizlogic.validation.single_use_redemption_sequential_then_parallel

**Claim.** A limit-overrun or single-use business-logic claim is confirmed only when parallel requests to the same single-use endpoint succeed where an identical sequential sequence fails, proving the limit was overrun rather than merely exercised twice.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, race_condition; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — warm: **do** repeat after a success; **observe** behaviour once a cached/derived artefact exists.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Race / TOCTOU attempt* — Identify the check and the use as TWO separate operations, and measure the gap between them.

<a id="bizlogic-test-an-oversized-refund-credit-or-payout-accepted-wi"></a>

## bizlogic.test.an_oversized_refund_credit_or_payout_accepted_wi

**Claim.** To decide this case, observe: Discard the report that says the endpoint validates nothing only when you could not establish the intended rule: without a stated cap, a documented maximum, or a control request showing the server enforces one, a large accepted amount proves nothing about a missing check.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="bizlogic-technique-back-navigation-reapplies-single-use-discount"></a>

## bizlogic.technique.back_navigation_reapplies_single_use_discount

**Claim.** A once-per-transaction limit enforced only in the forward UI flow is bypassed by navigating back to the discount step, because the server-side count is not tied to the transaction.

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

<a id="bizlogic-test-a-limit-overrun-or-single-use-business-logic-cla"></a>

## bizlogic.test.a_limit_overrun_or_single_use_business_logic_cla

**Claim.** To decide this case, observe: Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What must be TRUE server-side for this to bite?** — warm: **do** repeat after a success; **observe** behaviour once a cached/derived artefact exists.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="bizlogic-technique-encryption-oracle-reused-by-another-input"></a>

## bizlogic.technique.encryption_oracle_reused_by_another_input

**Claim.** An endpoint that encrypts attacker-controlled input with the server's key and returns the ciphertext becomes an oracle whenever another endpoint accepts ciphertext under the same algorithm.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="bizlogic-test-a-logic-flaw-reported-by-an-automated-scanner-wi"></a>

## bizlogic.test.a_logic_flaw_reported_by_an_automated_scanner_wi

**Claim.** To decide this case, observe: A reportable finding needs three things together: a stated rule the application is supposed to enforce, an observed deviation from it, and a consequence.

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

<a id="bizlogic-test-a-price-discount-or-total-that-the-server-echoes"></a>

## bizlogic.test.a_price_discount_or_total_that_the_server_echoes

**Claim.** To decide this case, observe: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="bizlogic-technique-start-then-abort-workflow-accumulates-persistent-credit"></a>

## bizlogic.technique.start_then_abort_workflow_accumulates_persistent_credit

**Claim.** When a workflow grants a durable credit at an intermediate step and does not roll it back on cancellation, an attacker accumulates credit by repeatedly starting a transaction and abandoning it without ever paying.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="bizlogic-technique-email-parser-discrepancy-confers-restricted-domain-access"></a>

## bizlogic.technique.email_parser_discrepancy_confers_restricted_domain_access

**Claim.** When the application authorises on the domain extracted from an email address, differing parsers let an address that passes validation be interpreted as a different domain, granting access to the restricted area.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder, filesystem_sink; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="bizlogic-auto-01"></a>

## bizlogic.auto.01

**Claim.** Weaknesses in this category identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application.

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

<a id="bizlogic-auto-02"></a>

## bizlogic.auto.02

**Claim.** Comments: The "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="bizlogic-auto-03"></a>

## bizlogic.auto.03

**Claim.** The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
