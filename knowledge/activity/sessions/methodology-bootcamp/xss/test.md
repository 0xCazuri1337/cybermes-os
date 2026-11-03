# test — ordered plan, each step with its expected information gain

Order is not stylistic. Each step below exists to *eliminate* a family of
explanations before the next step is chosen; running them out of order is what
produces both false positives and wasted windows.

## Step 0 — read the policy and the delivery contract (no request needed)

**Action:** capture `Content-Security-Policy`, `Content-Type`, `X-Content-Type-Options`,
`Set-Cookie` on the exact page.
**Information gain:** decides whether there is an HTML parser at all, and which
payload family can ever execute. A nonce/hash policy with no `unsafe-inline` removes
inline-handler payloads from the search space immediately
[xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload]; `application/json` with
`nosniff` removes the HTML-parsing hypothesis outright
[xss.fp_rule.json_api.content_type_json_is_not_html_execution]. One header block can
kill an entire branch of the hunt.

## Step 1 — unique-marker sweep, one marker per request

**Action:** ~8 mixed-case alphanumerics, one per parameter / body field / path segment
/ browser-set header [xss.test.entrypoints.unique_alnum_marker_sweep].
**Information gain:** distinguishes *no reflection* from *reflection in the wrong place*.
Negative result here is decisive: the probe value absent from the immediate response
means there is no reflected sink and the candidate must be dropped, not re-tested
[xss.prereq.reflected.request_data_in_immediate_response].

## Step 2 — name the context at every offset

**Action:** 80 characters left and right of each marker; name the context before
choosing a payload [xss.test.context.determine_injection_context].
**Information gain:** collapses the payload search space to one family and catches the
multi-context case where naming only the first offset hides the others.

## Step 3 — payload family for the named context

- body → new tags [xss.technique.html_between_tags.new_tags_required]
- quoted attribute → quote breakout + handler + repair
  [xss.technique.html_attribute.break_out_and_add_event_handler]
- URL attribute → `javascript:` [xss.technique.html_attribute.href_javascript_pseudo_protocol]
- script block → close the element [xss.technique.js_script_tag.html_parsed_before_js]
- JS string → terminate **and** repair [xss.technique.js_string.break_out_and_repair_syntax]
- template literal → `${…}`, no terminator
  [xss.technique.template_literal.expression_without_terminator]

**Information gain:** separates "the filter is strong" from "my payload was for the
wrong context". A miss here is a context error, not evidence of safety.

## Step 4 — read the transformation, then attack the decoder

**Action:** record exactly what came back; `'` = stripped, `\'` = backslash-escaped,
`&#39;` = entity-encoded, `%27` = URL-encoded, absent = denylist matched
[xss.test.bypass.entity_backslash_probe_sequence].
**Information gain:** tells you which decoder to attack rather than guessing. Entity
probe first in an HTML-decoded attribute context
[xss.bypass.filter.html_entity_decoding_of_attribute_values]; backslash prefix next when
quotes are backslash-escaped but the backslash itself is not
[xss.technique.js_string.unescaped_backslash_defeats_quote_escaping]; parentheses-free
invocation and template-literal probes when `()` is stripped
[xss.test.bypass.parens_free_and_template_literal_probes]
[xss.bypass.filter.parentheses_free_invocation].

## Step 5 — if it is DOM, prove the path with a debugger

**Action:** enumerate sink tokens in the downloaded bundle, breakpoint each source
read, step to the sink [xss.test.dom.enumerate_dangerous_sinks_in_bundle]
[xss.test.dom.prove_source_to_sink_path_with_debugger].
**Information gain:** the only thing that separates a DOM XSS finding from a grep hit.
Grepping source and sink names separately proves nothing about the path between them.

## Step 6 — confirm execution in a real browser, with two observables

**Action:** replay the exact saved request, keep every cookie and header, use a payload
with an unambiguous side effect [xss.test.execution.confirm_in_real_browser].
**Information gain:** converts "payload text is in the response" into "code ran".
A visible popup is not the only gate — alert can be suppressed while script runs — so
confirm with a second independent observable: network egress, DOM mutation, title change.

## Step 7 — prove reportability, not just execution

**Action:** split the PoC into Observation A (execution) and Observation B
(reportability — a second identity, or a completed same-origin state change)
[xss.validation.self_fired_marker_is_not_a_reportable_finding].
**Information gain:** this is where most hunts should stop honestly. Without B I file an
unconfirmed execution sink, not an impact claim.

## Step 8 — only then read the controls that cap impact

**Action:** with execution already confirmed, re-read CSP, HttpOnly and Trusted Types
on that exact response [xss.bypass.trusted_types.dom_sink_requires_policy]
[xss.bypass.csp_nonce_hash_or_strict_dynamic_gap].
**Information gain:** caps severity honestly instead of overstating it, and reminds me
that a nonce blocks injected inline script while leaving DOM sinks and dangling markup
open. Also check whether the policy itself is injectable —
`script-src-elem` can overwrite a nonce-based `script-src`
[xss.evidence.csp.script_src_elem_overwrite_defeats_nonce_policy] — and whether Trusted
Types is enforced without a default policy, in which case the sink throws
[xss.evidence.trusted_types.sink_throws_when_no_default_policy_returns_trustedscript].