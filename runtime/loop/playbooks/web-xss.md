# Hunt card — xss

52 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## xss.test.execution.confirm_in_real_browser

**Claim.** A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.entrypoints.unique_alnum_marker_sweep

**Claim.** A short unique alphanumeric marker echoed verbatim in the response, from every request-controlled entry point tested one at a time, is the pass condition that proves reflection exists before any payload is chosen.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.stored.two_identity_entry_to_exit_point_link

**Claim.** Stored XSS is proven only by storing a payload as one identity and loading the exit point as a second identity, because your own session re-rendering your own input proves storage and reflection, never cross-user execution.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change, race_condition, blind_confirmation)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.context.determine_injection_context

**Claim.** Reading the characters immediately before and after each reflection point tells you which of the six XSS contexts you are in, and the context selects the payload family, so no payload should be tried before the context is named.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.bypass.parens_free_and_template_literal_probes

**Claim.** When a filter blocks parentheses you switch to a parentheses-free invocation, and when the reflection lands inside backticks you use ${...} with no terminator at all - both are determined by what step 1 showed you in the response.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.dom.source_to_execution_sink

**Claim.** DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.dangling_markup.exfiltrates_without_script_execution

**Claim.** An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.validation.self_fired_marker_is_not_a_reportable_finding

**Claim.** A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.

**Procedure — item-authored procedure** (shapes: http_param_probe, filesystem_sink, state_change)

1. Separate your PoC into two observations.

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.js_string.break_out_and_repair_syntax

**Claim.** Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.js_string.unescaped_backslash_defeats_quote_escaping

**Claim.** An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.bypass.csp_nonce_hash_or_strict_dynamic_gap

**Claim.** A CSP only blocks inline or foreign script execution; nonces, hashes and strict-dynamic decide whether an injected payload can still run.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.reject_a_dom_or_reflected_xss_candidate_when_the

**Claim.** To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.reject_a_sanitizer_bypass_xss_claim_when_the_ren

**Claim.** To decide this case, observe: If the sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page

**Claim.** A reflected XSS on a page whose CSP is nonce-based is only exploitable if the injected markup executes on that same page and inherits its policy; a payload delivered on a page with no CSP header, or a different policy, is not covered by the nonce argument.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.signal.unique_alnum_marker_reflected_in_response

**Claim.** A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal for reflected XSS.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.json_response.embedded_into_html_document

**Claim.** A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.reject_a_reflected_xss_candidate_when_the_reflec

**Claim.** To decide this case, observe: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.reject_a_json_api_endpoint_reported_as_xss_when

**Claim.** To decide this case, observe: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.reject_a_stored_xss_candidate_when_the_submitted

**Claim.** To decide this case, observe: Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.variant.ht_observe_the_stored_xss_primitive

**Claim.** A stored-XSS sink can sit in a message header rather than a web request: the payload is stored alongside the message and later rendered by the mail client, where one click is enough to run it, so mail-rendering paths deserve the same stored-XSS attention as web pages.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.dom.url_fragment_and_query_as_source

**Claim.** The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.dom.sink_list_execution_capable

**Claim.** document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.dom.innerhtml_rejects_script_use_event_handlers

**Claim.** An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.dom.html_sink_marker_via_devtools_control_f

**Claim.** For DOM XSS you must seed the marker into a client-side source such as location.search and locate it in the live DOM with devtools Control+F, because the browser's View Source never shows JavaScript-injected nodes.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.html_attribute.new_event_handler_without_angle_brackets

**Claim.** In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.html_attribute.href_javascript_pseudo_protocol

**Claim.** An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.template_literal.expression_without_terminating

**Claim.** In a JavaScript template literal the payload does not need to escape the backtick, because the ${...} expression syntax executes during literal processing.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.bypass.filter.html_entity_decoding_of_attribute_values

**Claim.** HTML-encoding characters the filter blocks defeats it inside an event-handler attribute, because the browser HTML-decodes attribute values before JavaScript runs.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.validation.encoding_must_match_landing_context

**Claim.** An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.bypass.entity_backslash_probe_sequence

**Claim.** When a filter blocks your quote or tag characters, probe the decoder gap in a fixed order - HTML-entity-encode the blocked character first, then prepend a backslash to neutralise the app's own escaping - and a hit proves the filter normalises but does not neutralise.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.dom.enumerate_dangerous_sinks_in_bundle

**Claim.** Grepping a downloaded JS bundle for the concrete sink token set - innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln, eval, new Function, setTimeout/setInterval with a string first argument, and the jQuery html/append family - is what converts 'this page uses innerHTML somewhere' into a list of lines you can actually test.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.html_between_tags.new_tags_required

**Claim.** In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.html_encoding_characters_the_filter_blocks_defea

**Claim.** To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.reject_a_dom_based_xss_candidate_when_the_traced

**Claim.** To decide this case, observe: Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.test.a_payload_that_fires_an_alert_only_in_the_hunter

**Claim.** To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink.

**Procedure — item-authored procedure** (shapes: http_param_probe, state_change)

1. Separate your PoC into two observations.

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.dom_clobbering.named_element_shadows_configuration_object

**Claim.** Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.bypass.trusted_types.dom_sink_requires_policy

**Claim.** A nonce-based CSP only blocks injected inline script, so DOM sinks and dangling markup remain exploitable under the same policy.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## xss.technique.a_reflected_or_stored_cross_site_scripting_entry_point_is

**Claim.** A reflected or stored cross-site scripting entry point is confirmed when a chosen script payload executes in the page context rather than being escaped into inert text.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.validation.dom.url_encoded_source_kills_payload

**Claim.** If a DOM source value is URL-encoded before reaching the sink the markup payload cannot survive, making the candidate a false positive.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.bypass.filter.parentheses_free_invocation

**Claim.** A filter blocking parentheses is bypassed by invoking the function without them, for example with a throw statement and a global exception handler.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.html_attribute.break_out_and_add_event_handler

**Claim.** In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.js_script_tag.html_parsed_before_js

**Claim.** Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.signal.ht_this_is_not_trivial_as_modern_brow

**Claim.** Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.ht_escaping_script_tag_if_your_co

**Claim.** When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

## xss.lead.bbd_zere.es

**Claim.** Public writeup evidence for xss: self-XSS to account takeover.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.hth_example_of_an_insecure_implementat

**Claim.** The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

## xss.signal.dom.executable_source_to_sink_path

**Claim.** DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## xss.test.dom.prove_source_to_sink_path_with_debugger

**Claim.** A DOM XSS claim is only proven when the debugger shows an actual value flowing from a source read into an execution sink, because grepping source and sink names separately proves nothing about the path between them.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## xss.technique.ht_classify_the_final_execution_conte

**Claim.** The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.

**Procedure — State-changing verification** (shapes: state_change)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

## xss.signal.ht_the_problematic_javascript_part_o

**Claim.** The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## xss.technique.postmessage.receiver_must_validate_event_origin

**Claim.** A page that handles postMessage without validating event.origin accepts attacker-controlled input from any origin.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, race_condition)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

## xss.lead.bbd_jorianwoltjer.com

**Claim.** Public writeup evidence for xss: Blob-URL sandbox escape to XSS.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, encoding_ladder)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions
