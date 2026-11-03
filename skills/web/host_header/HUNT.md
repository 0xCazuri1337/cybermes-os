# HUNT runbook — host_header

**11 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py host_header web`).

Sources of steps: 0 item-authored, 11 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [host_header.technique.x_forwarded_host_overrides_a_validated_host_header](#host-header-technique-x-forwarded-host-overrides-a-validated-host-header) — Filter-bypass ladder
- [host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite](#host-header-validation-prove-host-injection-with-a-password-reset-url-rewrite) — Filesystem sink confirmation
- [host_header.test.calling_a_reflected_host_value_web_cache_poisoni](#host-header-test-calling-a-reflected-host-value-web-cache-poisoni) — Claim verification (no mechanical template matched)
- [host_header.test.a_server_returning_200_for_an_arbitrary_host_hea](#host-header-test-a-server-returning-200-for-an-arbitrary-host-hea) — Claim verification (no mechanical template matched)
- [host_header.test.an_attacker_controlled_hostname_appearing_inside](#host-header-test-an-attacker-controlled-hostname-appearing-inside) — Filesystem sink confirmation
- [host_header.test.the_convincing_host_header_validation_is_a_reque](#host-header-test-the-convincing-host-header-validation-is-a-reque) — Claim verification (no mechanical template matched)
- [host_header.technique.hth_if_you_come_across_api_json_in_an](#host-header-technique-hth-if-you-come-across-api-json-in-an) — Filesystem sink confirmation
- [host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist](#host-header-bypass-x-forwarded-host-trusted-without-a-known-proxy-allowlist) — Filter-bypass ladder
- [host_header.test.when_an_application_trusts_x_forwarded_host_or_e](#host-header-test-when-an-application-trusts-x-forwarded-host-or-e) — Claim verification (no mechanical template matched)
- [host_header.auto.06](#host-header-auto-06) — Single-parameter differential probe
- [host_header.auto.05](#host-header-auto-05) — Claim verification (no mechanical template matched)

<a id="host-header-technique-x-forwarded-host-overrides-a-validated-host-header"></a>

## host_header.technique.x_forwarded_host_overrides_a_validated_host_header

**Claim.** When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

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

<a id="host-header-validation-prove-host-injection-with-a-password-reset-url-rewrite"></a>

## host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite

**Claim.** The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-test-calling-a-reflected-host-value-web-cache-poisoni"></a>

## host_header.test.calling_a_reflected_host_value_web_cache_poisoni

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

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

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-test-a-server-returning-200-for-an-arbitrary-host-hea"></a>

## host_header.test.a_server_returning_200_for_an_arbitrary_host_hea

**Claim.** To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-test-an-attacker-controlled-hostname-appearing-inside"></a>

## host_header.test.an_attacker_controlled_hostname_appearing_inside

**Claim.** To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-test-the-convincing-host-header-validation-is-a-reque"></a>

## host_header.test.the_convincing_host_header_validation_is_a_reque

**Claim.** To decide this case, observe: Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-technique-hth-if-you-come-across-api-json-in-an"></a>

## host_header.technique.hth_if_you_come_across_api_json_in_an

**Claim.** On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.

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
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-bypass-x-forwarded-host-trusted-without-a-known-proxy-allowlist"></a>

## host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist

**Claim.** When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

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

<a id="host-header-test-when-an-application-trusts-x-forwarded-host-or-e"></a>

## host_header.test.when_an_application_trusts_x_forwarded_host_or_e

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
- **WHERE does the value arrive?** — header: **do** send it as a header; **observe** hop-by-hop stripping and header folding.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the header? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="host-header-auto-06"></a>

## host_header.auto.06

**Claim.** The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="host-header-auto-05"></a>

## host_header.auto.05

**Claim.** Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .

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
