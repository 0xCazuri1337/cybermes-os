# failure_analysis — expected vs actual vs wrong assumption vs next test

Three real failure modes of this class, taken from what the corpus says kills hunts.

## Failure 1 — the script-tag payload against an `innerHTML` sink

**Expected:** inject `<script>alert(document.domain)</script>` into a proven
`innerHTML` sink; the alert fires and the finding is written up.

**Actual:** nothing fires. No alert, no marker, no console error. The page looks
untouched, and a generic detector then claims XSS — a false-negative-then-false-positive
cycle from one weak PoC.

**Wrong assumption:** that "a script element in the DOM" implies execution. It does not.
The HTML fragment parser builds the element nodes, but the script element's *already
started* flag means it never runs, and `svg onload` does not fire either
[xss.technique.dom.innerhtml_rejects_script_use_event_handlers]
[xss.evidence.dom_sink.innerhtml_ignores_script_element_needs_event_handler]. I had
conflated "the payload was accepted by the sink" with "the sink executes it". The sink
list is not homogeneous: `document.write` and `writeln` go through the full parser and
*do* run a script element, while `innerHTML` does not
[xss.technique.dom.sink_list_execution_capable].

**Next test:** read which element the code actually assigns to, then swap in a construct
that fires an event on parse failure — `<img src=x onerror=alert(document.domain)>` —
and confirm the marker. And if the code later re-reads `.innerHTML` and passes it to
`document.write` or `eval`, the script element executes after that *second* step, so the
sink list must be followed to every use.

## Failure 2 — the payload is in the page and nothing happens (syntax repair)

**Expected:** terminate the JS string delimiter; the injected call executes.

**Actual:** the payload is visibly correct in the response source, and it never runs.

**Wrong assumption:** that breaking out is sufficient. Repair matters as much as
escaping: a leftover dangling fragment becomes a SyntaxError that kills the *entire*
script block, so the payload looks correct in the response yet never executes
[xss.technique.js_string.break_out_and_repair_syntax]
[xss.evidence.inside_a_quoted_javascript_string_literal_th]. I had also assumed my read
of the response was equivalent to the browser's parse — it is not, and the same
assumption produced the "script tag in `innerHTML`" error in Failure 1. The general
lesson: **I was reading source instead of observing execution.**

**Next test:** confirm in a real browser with two independent observables — network
egress and DOM/title mutation as well as `alert` — because a payload can execute with no
trace I chose to look for, and CSP report-only, Trusted Types default policies or
headless profiles can suppress `alert` while script still runs
[xss.test.execution.confirm_in_real_browser]. If execution is real and `alert` is
missing, that is not a failure.

## Failure 3 — I filed a reflection, and it was never reportable

**Expected:** marker reflects at the expected offset in a `text/html` response;
reflection plus unencoded output equals a finding; report it as reflected XSS.

**Actual:** triage rejects it. It was a JSON API, or the framework escapes on insertion,
or the value sat inside a comment/title/textarea where the payload is inert.

**Wrong assumption:** that reflection *is* the finding, and that the raw response body is
what the browser builds. Three distinct failures in one habit: (a) reflection is only the
first third of the chain — the second is whether those bytes can terminate their context
[xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context]; (b) a template
engine's escaping happens at insertion, so the response I read is a *pre-template*
artefact [xss.fp_rule.template_interpolation_is_escaped_by_the_framework_not_by_the_response];
(c) `Content-Type` decides whether there is a parser at all
[xss.fp_rule.json_api.content_type_json_is_not_html_execution]. Naming one context also
hides a second reflection elsewhere in the same response
[xss.test.context.determine_injection_context].

**Next test, in order:** name the context at every offset; read the rendered DOM rather
than the source; classify the sink against the execution-capable list; and before writing
the impact line, split the PoC into Observation A (execution) and Observation B
(reportability) [xss.validation.self_fired_marker_is_not_a_reportable_finding]. If I can
produce A but not B, I file an unconfirmed execution sink, not an impact claim.

## Failure 4 — over-rejecting on CSP, and closing a live DOM candidate

**Expected:** the live page ships `script-src 'nonce-…'`; my injected script does not
fire; close the finding as mitigated.

**Actual:** a DOM sink on the same page executes, or dangling markup exfiltrates the
rest of the response anyway.

**Wrong assumption:** that a nonce policy blocks XSS rather than one specific payload
family. A nonce is securely generated per load and unguessable, and the same value must
appear in the loading tag — that stops an injected *inline script tag*, and it does
nothing to a source reaching an existing execution sink, to dangling-markup
exfiltration, or to a clobbered configuration object
[xss.bypass.csp_nonce_hash_or_strict_dynamic_gap]. Two further traps: a `Report-Only`
header blocks nothing, and `script-src-elem` can *overwrite* a nonce-based `script-src`
if input is reflected into the policy
[xss.evidence.csp.script_src_elem_overwrite_defeats_nonce_policy].

**Next test:** read the policy on the exact response that executed, read the console for
the violation message, then enumerate what the policy leaves open before writing the
closure line
[xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page]
[xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload]. The symmetric error is
understating: treating `HttpOnly`/`SameSite` as an XSS mitigation when same-origin script
still acts with the victim's session
[xss.chain_link.cookie_posture.httponly_and_samesite_do_not_block_same_origin_script].

## Failure 5 — self-XSS filed as stored XSS

**Expected:** POST payload → it returns in my own response with 200 → marker persists on
reload → stored XSS with a CVSS vector.

**Actual:** the payload only ever renders for me. Persistence plus reflection is not
cross-site script execution; the missing half is the victim
[xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view].

**Wrong assumption:** that my own account counts as a second identity. It does not, and a
self-XSS delivery — pasting into my own address bar or console — crosses no user boundary
at all [xss.fp_rule.self_xss.payload_renders_only_in_submitter_browser].

**Next test:** sweep the *exit* points — admin/moderation queue, other users' listings and
profiles, notification email, export/CSV/PDF, webhook payloads — as a strictly
higher-privileged second identity, with one distinct marker per entry point
[xss.test.stored.two_identity_entry_to_exit_point_link]
[xss.chain_link.stored_payload_reaching_an_administrator_view]. The proof that escalates
is the privileged response or state change, never the marker firing.