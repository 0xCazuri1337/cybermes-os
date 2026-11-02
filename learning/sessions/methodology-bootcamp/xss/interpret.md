# interpret — result -> meaning -> next action

The ambiguous and negative rows are the ones that decide hunts, so they get the most
space.

## The single most common misdiagnosis: reflected vs. actually executes

| Result | Meaning | Next action |
|---|---|---|
| Marker present in response, unencoded, `text/html` | Reflection confirmed, execution untested. One third of the chain. | Go to context-naming then a context-appropriate payload [xss.test.context.determine_injection_context]. |
| Marker present only in a **302** body | Not rendered — the browser follows the redirect without parsing it. Not XSS yet. | Look for the value in a response the browser *does* parse [xss.signal.ht_this_is_not_trivial_as_modern_brow]. |
| Marker present, entity-encoded | Delivered as data, not markup. | Confirm the encoding matches the landing context; wrong-context encoding is a live bug [xss.validation.encoding_must_match_landing_context]. |
| **Payload visible in the response, no execution** | **The #1 misdiagnosis.** Text present is not code run. | Name the reason: script-element payload into an `innerHTML` sink never executes [xss.technique.dom.innerhtml_rejects_script_use_event_handlers]; a dangling JS fragment raises SyntaxError and kills the whole block [xss.technique.js_string.break_out_and_repair_syntax]. Swap payload family; do not report. |
| Execution confirmed in my browser only | Sink proven, impact unproven. | Produce Observation B or downgrade the claim honestly [xss.validation.self_fired_marker_is_not_a_reportable_finding]. |

## Execution confirmed but impact is capped

| Result | Meaning | Next action |
|---|---|---|
| Execution in an **opaque / sandboxed** origin, or a `data:`/`blob:` frame | Still a genuine script-execution defect, but the impact ceiling is that origin — no access to the app's cookies, storage or APIs. | Report the execution, state the ceiling explicitly, do not write "account takeover" [xss.chain_link.same_origin_authority.victim_session_actions]. |
| **CSP with a nonce/hash blocks the payload** | The markup defect is real but this payload family cannot run. Reporting "I injected a script tag and it did not fire" as a working XSS overstates it. | Reject or downgrade *this candidate* [xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload]; then enumerate what the policy leaves open — DOM sinks, dangling markup, clobbered config objects [xss.bypass.csp_nonce_hash_or_strict_dynamic_gap]. The policy is on the *exact* response; a different page or a `Report-Only` header inherits nothing [xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page]. |
| **CSP blocks inline script only** | Finding stands, impact changes. Inline handler payloads die; DOM sinks and dangling markup survive. | Re-test with a DOM-appropriate payload before downgrading [xss.bypass.trusted_types.dom_sink_requires_policy]. |
| **WAF / interstitial page** | The request was rewritten or intercepted before reaching the origin; the response you hold is not the application's. | Replay through a path that bypasses the interstitial, or record it as an unverified candidate — do not grade the origin's behaviour from an interstitial body. Confirm the CSP read in step 0 was on the real response [xss.bypass.csp_nonce_hash_or_strict_dynamic_gap]. |
| Execution with a **Trusted Types** sink and no default policy | The sink *throws*; the exception is the mitigation, not a bypass. | Do not claim bypass. Check for a default policy returning input unchanged, or a sink that bypasses the check [xss.evidence.trusted_types.sink_throws_when_no_default_policy_returns_trustedscript]. |

## Negative and misleading results

| Result | Meaning | Next action |
|---|---|---|
| Marker absent from the immediate response | No reflected sink. | Drop the candidate; re-test only if the field is stored rather than reflected [xss.prereq.reflected.request_data_in_immediate_response]. |
| Marker reflects, payload does not fire, DOM source present | Check whether the value was **URL-encoded in transit** (`encodeURIComponent`, or native encoding of `location.search`/`hash` in Chrome/Firefox/Safari). | Re-test with characters that are not percent-encoded, or trace the decode step — a non-encoded payload reaching `eval` refutes the encoding hypothesis [xss.validation.dom.url_encoded_source_kills_payload]. |
| Marker absent from the DOM, sink is `eval` | Expected: `eval` never renders text. | "Absent from the DOM" is not evidence of safety at an execution sink [xss.test.dom.html_sink_marker_via_devtools_control_f]. |
| No alert but a network beacon fired | The payload **did** execute. | Score as execution; `alert` was the wrong observable [xss.test.execution.confirm_in_real_browser]. |
| Payload executes only with a click | Real XSS, delivery-dependent. | `javascript:` in `href` always needs the click; that changes the delivery question, not the sink [xss.technique.html_attribute.href_javascript_pseudo_protocol]. |
| Marker executes in a data-exfiltration request, no script ran | Dangling markup / unterminated attribute. | Grade by what the response actually contains downstream, not by the fact a payload appeared [xss.technique.dangling_markup.exfiltrates_without_script_execution]. |
| Read-only brochureware page executes script | Still a finding. | Establish in-origin reach, rate on reach not on page-data sensitivity [xss.fp_rule.readonly_brochureware_page_does_not_clear_xss]. |
| Prototype polluted, no rendering | State corruption, not XSS. | Look for a gadget that reads the polluted property into an execution sink [xss.fp_rule.prototype_pollution.property_write_is_not_html_injection]. |