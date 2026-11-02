# reject_fp — misleading cases and the disproof test for each

The corpus carries **27 false-positive rules** for this class (14 promoted
`fp_rule` items plus the negative halves of the test and evidence items). These are the
ones that actually kill reports, with the disproof test stated for each. Every rule
here is two-sided: the rejection, and the observation that *un-rejects* it.

## 1. Reflected but encoded in a way that cannot break this context

**Reject when:** the reflected value appears only as HTML entities or percent/unicode
escapes that the browser decodes back to inert text in *that* context
[xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context]
[xss.evidence.reject_a_reflected_xss_candidate_when_the_re].
**Why it fools you:** the probe string comes back at the exact expected location, so
"the input is reflected" is satisfied and the report writes itself. Reflection is only
the first third; the second is whether the bytes can terminate their context.
**Disproof test:** inject the context-specific terminator and check the *rendered DOM*
— in an attribute, break the value with a quote; in the body, you need `<`. If the
quote is entity-encoded you cannot.
**Un-rejects when:** the encoding was applied for a *different* context (entity
encoding dropped inside a JS string, URL, CSS value or unquoted attribute), or the
entity is decoded and re-serialised before rendering
[xss.validation.encoding_must_match_landing_context].

## 2. The framework escapes it — the raw response is a pre-template artefact

**Reject when:** the value reaches the page only through a client-side template's
escaped interpolation or attribute binding, assigned via `textContent`/`setAttribute`
rather than concatenated into markup
[xss.fp_rule.template_interpolation_is_escaped_by_the_framework_not_by_the_response]
[xss.evidence.a_value_that_reaches_a_page_only_through_a_c].
**Why it fools you:** the parameter appears *unescaped* in the raw HTTP response body.
Vue's escaping happens with native browser APIs rather than string surgery, so the
response you read is not what the page builds.
**Disproof test:** determine whether the final insertion goes through a text node or
attribute assignment, or an HTML-string sink.
**Un-rejects when:** the same value also hits a raw-HTML sink on the same render path
(`v-html`, `innerHTML`, a markdown-to-HTML renderer, a server-side triple-brace or
`|safe` filter) — one raw sink is enough.

## 3. `application/json` is not an HTML execution context

**Reject when:** the response `Content-Type` is `application/json` and no client-side
path inserts the value into an HTML document
[xss.fp_rule.json_api.content_type_json_is_not_html_execution]
[xss.fp_rule.reflected_input_in_non_html_response_is_not_xss]
[xss.evidence.reject_a_json_api_endpoint_reported_as_xss_w].
**Why it fools you:** `POST {"name":"<script>alert(1)</script>"}` to `/api/profile`
comes back verbatim — a clean taint-to-reflection path with a classic payload, so
"attacker-controlled" and "unencoded" are both present and the report labels it XSS.
**Disproof test:** capture the full header block first. With `application/json` plus
`nosniff`, the browser renders the body as text in its viewer; no tokenizer runs.
**Un-rejects when:** the same path is reachable as `text/html` or a JSONP callback, or a
front end assigns the response into `innerHTML`, or a server renders the stored value
into a page for other users. Also note the mirror case: a JSON body **served as
`text/html`** and interpolated is an HTML injection point
[xss.technique.json_response.embedded_into_html_document].

## 4. The markup renderer is a stage, not a sink

**Reject when:** injection survives a server-side markup-to-HTML renderer (Markdown,
Textile, wiki syntax) but never reaches a script-execution context in the delivered page
[xss.fp_rule.markup_renderer_output_is_not_execution_until_a_second_stage_sink]
[xss.evidence.injection_that_survives_a_server_side_markup].
**Why it fools you:** the renderer's output is visibly full of angle brackets and the
injection is obvious in the raw HTML.
**Disproof test:** a wiki comment rendered to escaped `<p>`/`<strong>` is a formatting
bug; identify the **second stage** — which script, handler or navigation consumes this
markup, and whether it is reachable.
**Un-rejects when:** the renderer emits script-capable constructs by design (raw HTML
passthrough, an `<iframe>` block, inline handlers, `javascript:` links), or a
client-side viewer / print pipeline / email client re-injects it, or you have a
browser-confirmed execution trace.

## 5. The sanitizer output is inert in the page

**Reject a bypass claim when:** the rendered page shows the payload as literal text
with the dangerous markup stripped — no element with a live handler, no navigable
`javascript:`/`data:` URL, no beacon, no console error from your payload
[xss.fp_rule.sanitizer.output_observed_inert_in_page]
[xss.test.reject_a_sanitizer_bypass_xss_claim_when_the_ren].
**Why it fools you:** sanitizers have a long history of bypasses, so "the filter only
strips `<script>`, therefore `onerror` works" is an easy paper exploit.
**Disproof test:** what matters is the DOM the browser builds, not the payload you
typed. Inspect the rendered DOM and your callback endpoint.
**Un-rejects when:** a real element with a live handler is present and your callback
endpoint receives the request — that is a genuine bypass even if the sanitizer appeared
to strip `<script>`; and the rule does not apply where the sanitized string is
subsequently mutated or re-serialised.

## 6. The blocklist only deletes a keyword

**Not a rejection but a trap in the opposite direction:** a filter that deletes the
literal string `script` leaves the angle brackets intact, so the injected tag stays
well-formed and still executes
[xss.fp_rule.restricted_list_filter_that_deletes_a_keyword_leaves_a_live_payload].
**Disproof test:** inject the split-tag payload and see whether the filter operates on
the tag name, the whole element, or a substring. A parser-based sanitiser that rebuilds
from a permitted list neutralises it because the brackets are consumed with the
rejected tag; a substring delete does not. Check whether the allow-list itself admits a
dangerous attribute or URL scheme.

## 7. The DOM source reaches only a safe sink

**Reject when:** the traced source only reaches `textContent`, `innerText`, or
`setAttribute` with a **hardcoded non-event** name
[xss.fp_rule.sink_reachability.source_never_reaches_execution_sink]
[xss.test.reject_a_dom_based_xss_candidate_when_the_traced]
[xss.fp_rule.dom_clobbering.property_read_into_safe_sink].
**Why it fools you:** the marker echoed in the DOM makes the taint half feel 90% done.
**Disproof test:** classify the sink against the execution-capable list —
`document.write`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, string-argument
`setTimeout`, `Function()`, `script.src`/`iframe.src` navigations
[xss.technique.dom.sink_list_execution_capable].
**Un-rejects when:** the identical value, on the identical path, also reaches an
execution sink elsewhere, in a fallback branch, or for a different input shape; or the
`setAttribute` **name** is derived from the same tainted input (`onmouseover` recreates
the sink); or the clobbered/polluted property is consumed by a template that renders it
as markup.

## 8. Prototype pollution and DOM clobbering are state corruption, not injection

**Reject when:** the polluted property value is never read back into an HTML-executing
sink [xss.fp_rule.prototype_pollution.property_write_is_not_html_injection], or the
clobbered property is only read as a string into `textContent`, an attribute or a URL
fetch [xss.fp_rule.dom_clobbering.property_read_into_safe_sink].
**Why it fools you:** pollution is frequently rated critical/RCE and the tainted value
sits visibly on the prototype, so it gets filed as stored XSS "because the payload is in
the data model". Clobbering is code-*reuse*, not code-*injection*.
**Disproof test:** trace whether any template, `innerHTML` write or raw-HTML binding
consumes the property.
**Un-rejects when:** it does — then it is stored XSS reachable by every user of the app
[ xss.chain_link.prototype_pollution_to_dom_xss ] — or it reaches a code-execution
gadget, which is a stronger finding than the XSS I was about to file. The concrete gadget
shape: a config option read as `config.transport_url || defaults.transport_url` written
into a `script.src` [xss.evidence.prototype_pollution.transport_url_gadget_reaches_script_src].

## 9. Stored payload never reaches a second user's view

**Reject when:** the submitted payload never appears in any response served to another
user or role [xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view]
[xss.test.reject_a_stored_xss_candidate_when_the_submitted]
[xss.prereq.stored.two_step_store_then_second_user_view].
**Why it fools you:** you POST a payload, it returns in *your own* response with 200,
and the marker persists on reload — persistence plus reflection looks like stored XSS
and a CVSS vector is already chosen. The missing half is the victim.
**Disproof test:** enumerate exit points (listings, detail pages, search, profiles,
**admin/moderation queues**, dashboards, notification email, export/CSV/PDF, webhook
payloads, third-party integrations) and sweep them for your per-field markers as a
second identity.
**Un-rejects when:** any second surface renders the stored value. A mail-rendering
header is one such surface [xss.variant.ht_observe_the_stored_xss_primitive].

## 10. Self-XSS

**Reject when:** the payload can only be made to render by pasting attacker JavaScript
into the submitter's own address bar or console
[xss.fp_rule.self_xss.payload_renders_only_in_submitter_browser].
**Why it fools you:** the page genuinely reflects attacker markup into an HTML context
and genuinely lacks encoding — the code defect is real and scanners will flag it. But
nothing crosses a user boundary: no victim, no cross-user exposure.
**Disproof test:** ask whether a delivery path exists that does not require the victim to
paste anything.
**Un-rejects when:** a crafted URL or an auto-submitting form fires it in any other
user's browser, or the value is stored and rendered to others.

## 11. The CSP nonce closure — the most common wrong rejection

**Reject the candidate when** the live page ships `script-src` with a nonce or hash
source, no `unsafe-inline` and no `strict-dynamic`
[xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload]
[xss.test.reject_a_dom_or_reflected_xss_candidate_when_the].
**Disproof test:** read the policy on the **exact** response that executed the payload,
then read the console for the CSP violation.
**Three ways this closure is wrong:**
- A `Report-Only` header logs violations without blocking anything.
- The payload ran on a *different* response that carries no policy at all, or a
  different one — the nonce argument is per-response
  [xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page].
- The nonce is `strict-dynamic`-friendly, injectable, or the policy omits `default-src`
  and `script-src` so the permissive default applies — and, sharply,
  `script-src-elem` **can overwrite** a nonce-based `script-src`, so a reflected
  `report-uri` with a `;` in it defeats the whole policy
  [xss.evidence.csp.script_src_elem_overwrite_defeats_nonce_policy].
- And even when the closure holds for inline script, it is **not** a reason to close a
  DOM XSS candidate: DOM sinks, dangling markup and clobbered config objects remain
  open [xss.bypass.csp_nonce_hash_or_strict_dynamic_gap]
  [xss.bypass.trusted_types.dom_sink_requires_policy].

## 12. Rejections I must NOT make

Two corpus rules exist specifically to stop over-rejection:
`readonly_brochureware_page_does_not_clear_xss` — an anonymous read-only page still
executes script in every visitor's origin; rate on in-origin reach, not page-data
sensitivity [xss.fp_rule.readonly_brochureware_page_does_not_clear_xss]; and
`transport_security.tls_does_not_mitigate_same_origin_execution` — HTTPS changes
nothing, because `https` is part of the origin definition
[xss.impact.transport_security.tls_does_not_mitigate_same_origin_execution].