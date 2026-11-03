# hypothesize — keyed to observed signal, each falsifiable

Every hypothesis below names the observation that produced it **and** the observation
that would refute it. A hypothesis that cannot fail is an assertion; the corpus
refuses them on principle.

## H1 — the reflection is live and can terminate its context

**Keyed to:** marker returned verbatim in a `text/html` body [xss.signal.unique_alnum_marker_reflected_in_response].
**Claim:** the landing context is HTML body, so the failing invariant is
character-set trust — angle brackets survive to the tokenizer
[xss.technique.html_between_tags.new_tags_required].
**Refuted by:** the response entity-encodes `< > " '`, so the browser's tokenizer
never sees a delimiter and the value is delivered as data
[xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context].
**Falsifier I will actually run:** inject `<img src=x onerror=...>` and read the
**rendered DOM**, not the response body.

## H2 — the reflection is quoted-attribute, so the quote is the only lever

**Keyed to:** marker sits inside `="…"` with 80 chars either side naming an attribute
[xss.test.context.determine_injection_context].
**Claim:** `U+0022` is the only character that changes the parsing state, so
`" autofocus onfocus=… x="` executes with no angle brackets at all
[xss.technique.html_attribute.new_event_handler_without_angle_brackets].
**Refuted by:** the quote is escaped or the value re-quoted
[xss.technique.html_attribute.break_out_and_add_event_handler], or the live CSP has no
`unsafe-inline` so the handler is refused.

## H3 — the reflection lands in a URL-bearing attribute

**Keyed to:** marker is the value of `href`/`src`/`action` on a real element
[xss.technique.html_attribute.href_javascript_pseudo_protocol].
**Claim:** `javascript:` executes with no breakout; a WAF blocking `<` and `"` looks
completely clean while this still fires.
**Refuted by:** the value is URL-encoded so the scheme is no longer at the start, or
`javascript:` is stripped case-insensitively.

## H4 — the reflection lands in inline JavaScript

**Keyed to:** marker inside a `<script>` block.
**Claim:** closing the script element beats string surgery, because HTML is parsed
before JS [xss.technique.js_script_tag.html_parsed_before_js]; escaping the quote buys
nothing [xss.technique.ht_escaping_script_tag_if_your_co].
**Refuted by:** the closing sequence is escaped, or the value sits in an *external* JS
file where the browser never re-parses it as markup.

## H5 — the reflection lands in a JS string literal or template literal

**Keyed to:** response shows `var x = 'MARKER'` or `` var x = `MARKER` ``.
**Claim (string):** I must both terminate the delimiter and repair the trailing
script, or a SyntaxError kills the whole block and the payload never runs
[xss.technique.js_string.break_out_and_repair_syntax].
**Claim (template):** `${…}` executes during literal processing; nothing is broken
and nothing needs repair [xss.technique.template_literal.expression_without_terminator].
**Refuted by:** the application escapes the delimiter or the `$`/brace characters
[xss.technique.js_string.unescaped_backslash_defeats_quote_escaping], or the literal
is never evaluated at runtime.

## H6 — a DOM source reaches a safe sink, so this is not XSS

**Keyed to:** debugger shows `location.hash` flowing into `textContent`/`innerText` or
a hardcoded-name `setAttribute` [xss.fp_rule.sink_reachability.source_never_reaches_execution_sink].
**Claim:** the taint is real but the sink treats the value as text; no tokenizer runs.
**Refuted by:** the same value, same code path, also reaches
`innerHTML`/`document.write`/`eval`/string-`setTimeout` on another load, in a fallback
branch, or for a different input shape — or the `setAttribute` *name* is attacker-
influenced, which recreates the sink.

## H7 — the escaping is correct for a different context

**Keyed to:** entity encoding observed but the landing context is a JS string, URL, CSS
value or unquoted attribute [xss.validation.encoding_must_match_landing_context].
**Claim:** `&quot;` does not neutralise a `'` delimiter in JS; `';alert(1)//` still
breaks the string.
**Refuted by:** a vetted encoder is applied for the exact destination, or the value is
assigned as a property value on a sink that encodes automatically.

## H8 — the candidate is real but blocked by a live nonce/hash policy

**Keyed to:** `script-src 'nonce-…'` on the exact executing response
[xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload].
**Claim:** injected inline script and inline handlers are refused without
`unsafe-inline`.
**Refuted by:** `strict-dynamic` plus an already-trusted script, a matching
hash, `unsafe-inline`, or a `Report-Only` header that logs without blocking
[xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page].

## H9 — the stored payload reaches a privileged view

**Keyed to:** payload persists in a low-privilege field
[xss.prereq.stored.two_step_store_then_second_user_view].
**Claim:** escalation to administrator requires **two distinct identities** and the
proof is the privileged response, not the marker firing
[xss.chain_link.stored_payload_reaching_an_administrator_view].
**Refuted by:** the payload fires only in the submitter's own session — that is self-XSS
[xss.fp_rule.self_xss.payload_renders_only_in_submitter_browser].

## H10 — the filter normalises but does not neutralise

**Keyed to:** response shows `\'` or `&#39;` rather than the raw character
[xss.test.bypass.entity_backslash_probe_sequence].
**Claim:** a decoding-order mismatch defeats it — the browser HTML-decodes attribute
values *before* JS is interpreted, so an encoded quote becomes a real delimiter
[xss.bypass.filter.html_entity_decoding_of_attribute_values].
**Refuted by:** the app re-encodes after decoding, or the sink is `textContent` and
receives the still-encoded value without HTML decoding.

## H11 — the pollute/clobber primitive has no execution sink

**Keyed to:** `Object.prototype` polluted or a named element shadowing a global
[xss.fp_rule.prototype_pollution.property_write_is_not_html_injection]
[xss.fp_rule.dom_clobbering.property_read_into_safe_sink].
**Claim:** a property *write* is state corruption, not HTML injection; nothing has
rendered it.
**Refuted by:** the polluted property is later consumed by a templating engine or a
raw-HTML binding — then it is stored XSS — or reaches a code-execution gadget, which
is a stronger finding than the XSS I was about to file.