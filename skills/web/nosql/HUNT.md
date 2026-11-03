# HUNT runbook — nosql

**14 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py nosql web`).

Sources of steps: 0 item-authored, 14 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [nosql.signal.type_anomalous_field_changes_result_shape](#nosql-signal-type-anomalous-field-changes-result-shape) — Claim verification (no mechanical template matched)
- [nosql.technique.operator_object_bypasses_authentication](#nosql-technique-operator-object-bypasses-authentication) — Filesystem sink confirmation
- [nosql.technique.regex_oracle_character_by_character_leak](#nosql-technique-regex-oracle-character-by-character-leak) — Claim verification (no mechanical template matched)
- [nosql.bypass.blocklist_bypass_via_top_level_where_operator](#nosql-bypass-blocklist-bypass-via-top-level-where-operator) — Filter-bypass ladder
- [nosql.validation.three_probe_operator_and_field_allowlist_test](#nosql-validation-three-probe-operator-and-field-allowlist-test) — Filter-bypass ladder
- [nosql.validation.boolean_operator_probe_is_the_observation_that_distinguishes_injection_from_normal_filtering](#nosql-validation-boolean-operator-probe-is-the-observation-that-distinguishes-injection-from-normal-filtering) — Filter-bypass ladder
- [nosql.test.a_json_list_endpoint_that_returns_every_record_t](#nosql-test-a-json-list-endpoint-that-returns-every-record-t) — Claim verification (no mechanical template matched)
- [nosql.bypass.a_server_side_filter_is_not_a_defence_against_client_supplied_operators](#nosql-bypass-a-server-side-filter-is-not-a-defence-against-client-supplied-operators) — Single-parameter differential probe
- [nosql.test.adding_a_server_side_filter_clause_such_as_owner](#nosql-test-adding-a-server-side-filter-clause-such-as-owner) — Claim verification (no mechanical template matched)
- [nosql.test.a_nosql_injection_finding_requires_the_attacker](#nosql-test-a-nosql-injection-finding-requires-the-attacker) — Claim verification (no mechanical template matched)
- [nosql.test.returning_more_documents_than_the_caller_should](#nosql-test-returning-more-documents-than-the-caller-should) — Claim verification (no mechanical template matched)
- [nosql.bypass.$nin_and_array_valued_parameters_defeat_a_single_scalar_equality_check](#nosql-bypass-nin-and-array-valued-parameters-defeat-a-single-scalar-equality-check) — Filter-bypass ladder
- [nosql.auto.t.e3ec9702](#nosql-auto-t-e3ec9702) — Claim verification (no mechanical template matched)
- [nosql.auto.t.edfddaa9](#nosql-auto-t-edfddaa9) — Filesystem sink confirmation

<a id="nosql-signal-type-anomalous-field-changes-result-shape"></a>

## nosql.signal.type_anomalous_field_changes_result_shape

**Claim.** A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than being rejected.

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

<a id="nosql-technique-operator-object-bypasses-authentication"></a>

## nosql.technique.operator_object_bypasses_authentication

**Claim.** Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="nosql-technique-regex-oracle-character-by-character-leak"></a>

## nosql.technique.regex_oracle_character_by_character_leak

**Claim.** A $regex operator object in a lookup field turns the response into a boolean oracle, letting an attacker recover a secret token one character at a time by repeated prefix guesses against an unauthenticated endpoint.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — front_back: **do** front end filters, back end parses; **observe** a request the front end 'cleared' but the back end acted on.
- **AS whom are you testing?** — anonymous: **do** send with no credentials; **observe** whether the route is reachable pre-auth.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="nosql-bypass-blocklist-bypass-via-top-level-where-operator"></a>

## nosql.bypass.blocklist_bypass_via_top_level_where_operator

**Claim.** An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, filesystem_sink, blind_confirmation; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="nosql-validation-three-probe-operator-and-field-allowlist-test"></a>

## nosql.validation.three_probe_operator_and_field_allowlist_test

**Claim.** A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, filesystem_sink; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="nosql-validation-boolean-operator-probe-is-the-observation-that-distinguishes-injection-from-normal-filtering"></a>

## nosql.validation.boolean_operator_probe_is_the_observation_that_distinguishes_injection_from_normal_filtering

**Claim.** The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="nosql-test-a-json-list-endpoint-that-returns-every-record-t"></a>

## nosql.test.a_json_list_endpoint_that_returns_every_record_t

**Claim.** To decide this case, observe: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="nosql-bypass-a-server-side-filter-is-not-a-defence-against-client-supplied-operators"></a>

## nosql.bypass.a_server_side_filter_is_not_a_defence_against_client_supplied_operators

**Claim.** Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filter-bypass ladder* — First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).

<a id="nosql-test-adding-a-server-side-filter-clause-such-as-owner"></a>

## nosql.test.adding_a_server_side_filter_clause_such_as_owner

**Claim.** To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.

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

<a id="nosql-test-a-nosql-injection-finding-requires-the-attacker"></a>

## nosql.test.a_nosql_injection_finding_requires_the_attacker

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

<a id="nosql-test-returning-more-documents-than-the-caller-should"></a>

## nosql.test.returning_more_documents_than_the_caller_should

**Claim.** To decide this case, observe: Mechanism: Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.

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

<a id="nosql-bypass-nin-and-array-valued-parameters-defeat-a-single-scalar-equality-check"></a>

## nosql.bypass.$nin_and_array_valued_parameters_defeat_a_single_scalar_equality_check

**Claim.** A filter that only ever compares one scalar against one submitted value is bypassable with array-valued and negated operators such as $nin and $ne, which change the comparison's shape rather than its content.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — content: **do** obtain content from outside the intended scope; **observe** the returned bytes and where they came from.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="nosql-auto-t-e3ec9702"></a>

## nosql.auto.t.e3ec9702

**Claim.** "abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields.

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

<a id="nosql-auto-t-edfddaa9"></a>

## nosql.auto.t.edfddaa9

**Claim.** These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages.

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
