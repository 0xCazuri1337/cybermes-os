# HUNT runbook — sqli

**27 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py sqli web`).

Sources of steps: 0 item-authored, 27 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [sqli.validation.single_variable_differential](#sqli-validation-single-variable-differential) — Claim verification (no mechanical template matched)
- [sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable](#sqli-validation-one-variable-at-a-time-is-the-only-way-the-differential-is-attributable) — Filter-bypass ladder
- [sqli.bypass.waf_normalization_encoding](#sqli-bypass-waf-normalization-encoding) — Filter-bypass ladder
- [sqli.test.a_sqli_finding_is_only_validated_when_one_variab](#sqli-test-a-sqli-finding-is-only-validated-when-one-variab) — Claim verification (no mechanical template matched)
- [sqli.signal.async_query_oast_signal](#sqli-signal-async-query-oast-signal) — Filesystem sink confirmation
- [sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload](#sqli-validation-a-search-box-taking-a-fts-query-string-is-not-covered-by-the-quote-payload) — Single-parameter differential probe
- [sqli.technique.hth_union_select_null_union_se](#sqli-technique-hth-union-select-null-union-se) — Claim verification (no mechanical template matched)
- [sqli.test.a_500_or_generic_error_page_triggered_by_malform](#sqli-test-a-500-or-generic-error-page-triggered-by-malform) — Claim verification (no mechanical template matched)
- [sqli.technique.boolean_character_extraction](#sqli-technique-boolean-character-extraction) — Blind / out-of-band confirmation
- [sqli.technique.orderby_column_count_probe](#sqli-technique-orderby-column-count-probe) — Claim verification (no mechanical template matched)
- [sqli.validation.verbose_error_confirmation](#sqli-validation-verbose-error-confirmation) — Blind / out-of-band confirmation
- [sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co](#sqli-technique-sql-injection-is-confirmed-by-a-boolean-differential-a-co) — Claim verification (no mechanical template matched)
- [sqli.signal.quote_and_boolean_differential](#sqli-signal-quote-and-boolean-differential) — Claim verification (no mechanical template matched)
- [sqli.technique.union_null_type_probe](#sqli-technique-union-null-type-probe) — Claim verification (no mechanical template matched)
- [sqli.test.ht_therefore_a_good_way_to_discover](#sqli-test-ht-therefore-a-good-way-to-discover) — Blind / out-of-band confirmation
- [sqli.variant.ht_example_query_built_by_the_backend](#sqli-variant-ht-example-query-built-by-the-backend) — Claim verification (no mechanical template matched)
- [sqli.test.ht_if_the_specified_file_exists_ms_a](#sqli-test-ht-if-the-specified-file-exists-ms-a) — Filesystem sink confirmation
- [sqli.technique.ht_top_accepts_as_argument_an_integer](#sqli-technique-ht-top-accepts-as-argument-an-integer) — Claim verification (no mechanical template matched)
- [sqli.auto.02](#sqli-auto-02) — Encoding / normalisation ladder
- [sqli.auto.03](#sqli-auto-03) — Encoding / normalisation ladder
- [sqli.technique.ht_0_union_select_from_flag_it_s_p](#sqli-technique-ht-0-union-select-from-flag-it-s-p) — Filesystem sink confirmation
- [sqli.technique.ht_mysql_union_based_sql_union_selec](#sqli-technique-ht-mysql-union-based-sql-union-selec) — Filter-bypass ladder
- [sqli.technique.ht_union_select_1_2_3_4_group_con](#sqli-technique-ht-union-select-1-2-3-4-group-con) — Claim verification (no mechanical template matched)
- [sqli.technique.ht_select_from_fn_my_permissions_nu](#sqli-technique-ht-select-from-fn-my-permissions-nu) — Claim verification (no mechanical template matched)
- [sqli.test.ht_the_currently_executing_sql_query](#sqli-test-ht-the-currently-executing-sql-query) — Filesystem sink confirmation
- [sqli.auto.01](#sqli-auto-01) — Filesystem sink confirmation
- [sqli.technique.ht_here_s_how_to_retrieve_the_schema](#sqli-technique-ht-here-s-how-to-retrieve-the-schema) — Claim verification (no mechanical template matched)

<a id="sqli-validation-single-variable-differential"></a>

## sqli.validation.single_variable_differential

**Claim.** A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.

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

<a id="sqli-validation-one-variable-at-a-time-is-the-only-way-the-differential-is-attributable"></a>

## sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable

**Claim.** A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, blind_confirmation; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — cached: **do** add a cache-buster, then repeat without; **observe** whether a cached 200 masked the real path.
- **What must be TRUE server-side for this to bite?** — post_write: **do** trigger after a legitimate write; **observe** a stored value re-read on a later request.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="sqli-bypass-waf-normalization-encoding"></a>

## sqli.bypass.waf_normalization_encoding

**Claim.** WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, encoding_ladder; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — proxied: **do** request through the proxy/CDN; **observe** normalisation the proxy adds or strips.
- **WHAT transformation sits between you and the sink?** — url: **do** send it percent-encoded once; **observe** whether the decode happens before or after validation.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

You are at the `url` rung. Continue the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat through the proxy? Compare against the ORIGIN directly if reachable — the difference is the proxy's contribution.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Encoding / normalisation ladder* — Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.

<a id="sqli-test-a-sqli-finding-is-only-validated-when-one-variab"></a>

## sqli.test.a_sqli_finding_is_only_validated_when_one_variab

**Claim.** To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.

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

<a id="sqli-signal-async-query-oast-signal"></a>

## sqli.signal.async_query_oast_signal

**Claim.** If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, blind_confirmation; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **WHERE does the value arrive?** — cookie: **do** send it in a cookie; **observe** server-side cookie reconstruction.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the cookie? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="sqli-validation-a-search-box-taking-a-fts-query-string-is-not-covered-by-the-quote-payload"></a>

## sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload

**Claim.** In a full-text search parameter the attacker-controlled text is a query language, not a string literal, so single-quote and UNION payloads test nothing and the injection point is the operator's own grammar.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink; steps from template)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **WHERE does the value arrive?** — query: **do** send it in the query string; **observe** URL-decoded value as the app reconstructs it.
- **What must be TRUE server-side for this to bite?** — warm: **do** repeat after a success; **observe** behaviour once a cached/derived artefact exists.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat in the query? Move the SAME value to a different location (query / path / body / header / cookie). A filter on one location says nothing about the others.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="sqli-technique-hth-union-select-null-union-se"></a>

## sqli.technique.hth_union_select_null_union_se

**Claim.** A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.

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

<a id="sqli-test-a-500-or-generic-error-page-triggered-by-malform"></a>

## sqli.test.a_500_or_generic_error_page_triggered_by_malform

**Claim.** To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.

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

<a id="sqli-technique-boolean-character-extraction"></a>

## sqli.technique.boolean_character_extraction

**Claim.** Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.

**Procedure — Blind / out-of-band confirmation** (shapes: blind_confirmation; steps from template)

1. Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.
2. Then test the vulnerable condition. Absence of a callback is only meaningful once the channel is proven.
3. Record the callback evidence (resolved host, token, timestamp) — a blind result with no artefact is not reportable.

**Record:** channel self-test, callback artefact, timing

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-technique-orderby-column-count-probe"></a>

## sqli.technique.orderby_column_count_probe

**Claim.** Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.

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

<a id="sqli-validation-verbose-error-confirmation"></a>

## sqli.validation.verbose_error_confirmation

**Claim.** A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.

**Procedure — Blind / out-of-band confirmation** (shapes: blind_confirmation; steps from template)

1. Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.
2. Then test the vulnerable condition. Absence of a callback is only meaningful once the channel is proven.
3. Record the callback evidence (resolved host, token, timestamp) — a blind result with no artefact is not reportable.

**Record:** channel self-test, callback artefact, timing

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-technique-sql-injection-is-confirmed-by-a-boolean-differential-a-co"></a>

## sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co

**Claim.** SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.

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

<a id="sqli-signal-quote-and-boolean-differential"></a>

## sqli.signal.quote_and_boolean_differential

**Claim.** A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.

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

<a id="sqli-technique-union-null-type-probe"></a>

## sqli.technique.union_null_type_probe

**Claim.** UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-test-ht-therefore-a-good-way-to-discover"></a>

## sqli.test.ht_therefore_a_good_way_to_discover

**Claim.** When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.

**Procedure — Blind / out-of-band confirmation** (shapes: blind_confirmation; steps from template)

1. Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.
2. Then test the vulnerable condition. Absence of a callback is only meaningful once the channel is proven.
3. Record the callback evidence (resolved host, token, timestamp) — a blind result with no artefact is not reportable.

**Record:** channel self-test, callback artefact, timing

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-variant-ht-example-query-built-by-the-backend"></a>

## sqli.variant.ht_example_query_built_by_the_backend

**Claim.** A search box wired into a full-text MATCH ... AGAINST clause in boolean mode is its own injection flavour: the search term is concatenated inside the quoted argument, so the tester should probe the quote and the boolean-mode operators rather than a plain WHERE value.

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

<a id="sqli-test-ht-if-the-specified-file-exists-ms-a"></a>

## sqli.test.ht_if_the_specified_file_exists_ms_a

**Claim.** MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.

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

<a id="sqli-technique-ht-top-accepts-as-argument-an-integer"></a>

## sqli.technique.ht_top_accepts_as_argument_an_integer

**Claim.** Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.

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

<a id="sqli-auto-02"></a>

## sqli.auto.02

**Claim.** For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.

**Procedure — Encoding / normalisation ladder** (shapes: encoding_ladder; steps from template)

1. Build the ladder BEFORE probing: raw, single-encoded, double-encoded, and over-long variants of the same logical value.
2. Send each rung with the baseline procedure (one variable changed).
3. Record which rung first produces an effect. That rung identifies the decoding layer the application applies, and where the check and the decode disagree.
4. Verify WHERE normalisation happened: reflect the value in a way only the server could compute. Client-side canonicalisation proves nothing about the server.

**Record:** rung that first differed, decoding layer inferred, server-side reflection evidence

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What sits between client and sink?** — http2: **do** negotiate h2/h2c; **observe** frame-level parsing differences.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-auto-03"></a>

## sqli.auto.03

**Claim.** Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.

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

<a id="sqli-technique-ht-0-union-select-from-flag-it-s-p"></a>

## sqli.technique.ht_0_union_select_from_flag_it_s_p

**Claim.** Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.

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

<a id="sqli-technique-ht-mysql-union-based-sql-union-selec"></a>

## sqli.technique.ht_mysql_union_based_sql_union_selec

**Claim.** MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-technique-ht-union-select-1-2-3-4-group-con"></a>

## sqli.technique.ht_union_select_1_2_3_4_group_con

**Claim.** Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-technique-ht-select-from-fn-my-permissions-nu"></a>

## sqli.technique.ht_select_from_fn_my_permissions_nu

**Claim.** An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.

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

<a id="sqli-test-ht-the-currently-executing-sql-query"></a>

## sqli.test.ht_the_currently_executing_sql_query

**Claim.** On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.

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

<a id="sqli-auto-01"></a>

## sqli.auto.01

**Claim.** If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="sqli-technique-ht-here-s-how-to-retrieve-the-schema"></a>

## sqli.technique.ht_here_s_how_to_retrieve_the_schema

**Claim.** On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.

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
