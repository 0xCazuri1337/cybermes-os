# generalize — common, uncommon and defensive variants

## Common variants (expect these; do not re-derive them)

| Variant | Shape | Anchor |
|---|---|---|
| Reflected in HTML body | new tags required, no delimiter to escape | [xss.technique.html_between_tags.new_tags_required] |
| Reflected in quoted attribute | quote + handler + repair, no angle brackets | [xss.technique.html_attribute.new_event_handler_without_angle_brackets] [xss.evidence.attr_context.autofocus_onfocus_without_angle_brackets] |
| Reflected in URL attribute | `javascript:` scheme, no breakout | [xss.technique.html_attribute.href_javascript_pseudo_protocol] |
| Reflected in inline script | close the element (HTML parsed before JS) | [xss.technique.js_script_tag.html_parsed_before_js] [xss.technique.ht_escaping_script_tag_if_your_co] |
| Reflected in JS string | terminate **and** repair | [xss.technique.js_string.break_out_and_repair_syntax] |
| DOM via URL source | fragment first, then query, then 404 path | [xss.technique.dom.url_fragment_and_query_as_source] [xss.test.dom.html_sink_marker_via_devtools_control_f] |
| DOM via `innerHTML` | `img`/`iframe` event, **not** a script element | [xss.technique.dom.innerhtml_rejects_script_use_event_handlers] [xss.evidence.dom_sink.innerhtml_ignores_script_element_needs_event_handler] |
| Stored, low-priv → admin view | two identities, privileged response as proof | [xss.chain_link.stored_payload_reaching_an_administrator_view] |
| postMessage without origin check | receiver-side allow-list is the boundary | [xss.technique.postmessage.receiver_must_validate_event_origin] [xss.prerequisite.hth_however_if_the_receiving_applicat] |

## Uncommon variants (the ones a generic scanner misses)

- **Attribute breakout with zero angle brackets.** `" autofocus onfocus=… x="` fires
  against a filter that strips only `<` `>`; two independent mechanisms (autofocus takes
  focus without interaction, onfocus is the handler) do the work
  [xss.evidence.attr_context.autofocus_onfocus_without_angle_brackets]. Conclusion order
  matters: name the context first, try attribute breakout before between-tags, because a
  WAF that blocks `<` looks clean while this still fires.
- **Template-literal injection.** `${…}` executes during literal processing; the literal
  stays syntactically intact, nothing is broken, nothing repaired, and a filter watching
  backticks/quotes/angle brackets sees none of them
  [xss.technique.template_literal.expression_without_terminator].
- **Parentheses-free invocation.** `onerror=alert;throw 1` calls `alert` through the
  global exception handler — parentheses are the single most commonly filtered character
  and this defeats it with no encoding trick
  [xss.bypass.filter.parentheses_free_invocation]
  [xss.test.bypass.parens_free_and_template_literal_probes].
- **Entity-then-backslash decoder gap.** HTML-entity-encode the blocked quote, then
  prepend a backslash to neutralise the app's own escaping; the browser HTML-decodes
  attribute values *before* JS runs, so `&#39;` becomes a real delimiter
  [xss.bypass.filter.html_entity_decoding_of_attribute_values]
  [xss.technique.js_string.unescaped_backslash_defeats_quote_escaping]
  [xss.test.bypass.entity_backslash_probe_sequence].
- **Dangling markup / unterminated attribute.** The tokenizer stays in the
  attribute-value state until the *next* quote anywhere in the document, so the rest of
  the response — CSRF tokens, email content, financial data — is sent to the attacker's
  URL with **no script execution**
  [xss.technique.dangling_markup.exfiltrates_without_script_execution]
  [xss.evidence.dangling_markup.img_src_swallows_following_page_markup]. Evidence is an
  outbound request in the network log, not an alert.
- **CSP reflection into `script-src-elem`.** A reflected `report-uri` plus a `;` lets the
  attacker append a directive that overwrites a nonce-based `script-src` entirely
  [xss.evidence.csp.script_src_elem_overwrite_defeats_nonce_policy].
- **DOM clobbering as configuration control.** Injected `id`/`name` attributes create a
  `window`/`document` property that resolves ahead of built-in APIs; a form+anchor pair
  fabricates a form-like object with `method` and `action`
  [xss.technique.dom_clobbering.named_element_shadows_configuration_object]. This is why a
  CSP blocking inline script may still leave the page exploitable.
- **Prototype pollution → `script.src` gadget.** `config.transport_url || defaults.transport_url`
  where the config object has no own property inherits the attacker's domain from
  `Object.prototype` [xss.chain_link.prototype_pollution_to_dom_xss]
  [xss.evidence.prototype_pollution.transport_url_gadget_reaches_script_src].
- **Stored sink in a mail header.** The mail client renders it and one click executes
  [xss.variant.ht_observe_the_stored_xss_primitive].
- **Service-worker XSS.** Needs attacker JS *served from the target origin* plus an XSS
  that registers the worker [xss.prerequisite.ht_attack_creating_a_service_worker]
  [xss.prerequisite.ht_this_is_the_code_that_must_be_uplo]
  [xss.impact.ht_for_example_javascript_var_sw].
- **Extension context triage.** MV3 service worker has no DOM, so it is a code-injection
  review; a sandboxed page is the documented CSP exception
  [xss.technique.ht_classify_the_final_execution_conte]
  [xss.signal.ht_the_problematic_javascript_part_o].
- **HTML injection escalating past its routine severity.** A link element to an
  attacker-controlled domain turns HTML injection into a credential-harvesting redirect
  or a bridge to a previously found XSS page
  [xss.impact.hth_you_will_notice_the_h1_tag_getti].

## Defensive variants (controls that reshape the finding)

| Control | What it actually blocks | What it does **not** block | Anchor |
|---|---|---|---|
| CSP `script-src 'nonce-…'` / hash | injected inline script and inline handlers | DOM sinks, dangling markup, clobbered config, `script-src-elem` overwrite | [xss.bypass.csp_nonce_hash_or_strict_dynamic_gap] [xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload] |
| `strict-dynamic` | an injected tag alone, even with a broad host allowlist | — (trust propagates only from already-trusted scripts) | [xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page] |
| `'unsafe-eval'` only | nothing for inline handlers — it buys a tester nothing here | onerror-style payloads still need `unsafe-inline` | [xss.prerequisite.ht_script_src_self_unsafe_eval] |
| `require-trusted-types-for 'script'` | plain strings at DOM sinks — the sink **throws** without a default policy | sinks reached by a default policy returning input unchanged; indirect sinks that bypass the check | [xss.bypass.trusted_types.dom_sink_requires_policy] [xss.evidence.trusted_types.sink_throws_when_no_default_policy_returns_trustedscript] |
| `HttpOnly` + `SameSite=Strict` | `document.cookie` reads; cross-site request delivery | same-origin script acting with the victim's session — neither flag is an XSS mitigation | [xss.chain_link.cookie_posture.httponly_and_samesite_do_not_block_same_origin_script] |
| Anti-CSRF token / Origin check | cross-site forged requests | same-origin script that reads the token out of the page | [xss.chain_link.csrf_token_read_defeats_csrf_defence] |
| HTTPS | channel tampering between client and server | same-origin execution — `https` is part of the origin | [xss.impact.transport_security.tls_does_not_mitigate_same_origin_execution] |
| Output encoding | the delimiter **for the matched context** | the same value landing in a different context | [xss.validation.encoding_must_match_landing_context] |

**The defensive variant that inverts a finding:** a permitted-list sanitiser is not
automatically sufficient — if the allow-list itself admits a dangerous attribute or URL
scheme, it is incomplete
[xss.fp_rule.restricted_list_filter_that_deletes_a_keyword_leaves_a_live_payload]. And a
keyword-only blocklist is not a control at all.