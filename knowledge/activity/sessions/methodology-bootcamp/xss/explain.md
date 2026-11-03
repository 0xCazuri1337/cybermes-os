# explain — cross-site scripting from first principles

## The chain, end to end

An XSS report is a claim about a **parser**, not about a filter. The full chain has
seven links and a hunt dies at any of them:

1. **attacker input** — a request-controlled surface (query, body, path, `Referer`,
   stored field, or a purely client-side source such as `location.hash` that never
   reaches the server) [xss.prereq.reflected.request_data_in_immediate_response]
   [xss.technique.dom.url_fragment_and_query_as_source]. The precondition for
   reflected XSS is that the value reappears in the *same* immediate response
   [xss.prereq.reflected.request_data_in_immediate_response]; for stored XSS it is
   two separate actions — a write, then a render in another user's response
   [xss.prereq.stored.two_step_store_then_second_user_view].
2. **parser** — the browser's tokenizer decides what the bytes *mean*. HTML is parsed
   before JavaScript is parsed, which is why closing a `<script>` element beats
   fighting string syntax [xss.technique.js_script_tag.html_parsed_before_js].
3. **normalisation / filter** — a blocklist rewrites the string (strips `script`,
   escapes quotes, drops parentheses). A keyword-only delete leaves the angle
   brackets behind so the tag re-assembles
   [xss.fp_rule.restricted_list_filter_that_deletes_a_keyword_leaves_a_live_payload].
4. **validation** — encoding applied at the wrong layer. Output encoding is
   context-specific, so an encoder correct for HTML body text does nothing for a
   JavaScript string or a URL [xss.validation.encoding_must_match_landing_context].
5. **trust decision** — the application treats its own bytes as safe because they came
   from its own origin. That is the whole bug: trust is inherited from the origin,
   not earned by the content [xss.prerequisite.bis_6_injections_html_xss_etc_i].
6. **sink** — the point where the interpreter acts: a script element, an event
   handler, `innerHTML`, `document.write`, `eval`, a `script.src`
   [xss.technique.a_reflected_or_stored_cross_site_scripting_entry_point_is].
7. **observable result** — code runs *in the victim's origin*, which is the only
   thing that makes it cross-site rather than cosmetic.

## The failing invariant, named separately per context

The invariant is never "the app must escape input". It is **"no attacker-controlled
byte may terminate the syntactic unit it lands in, unless that termination alone
yields execution."** That reads differently in each context, and a hunter who
generalises from one context will misread every other one:

| Context | Failing invariant | What actually breaks the unit | Corpus anchor |
|---|---|---|---|
| **HTML body / between tags** | no attacker byte may introduce a new tag | only `<` and `>`; there is no delimiter to escape, so entirely new markup is required | [xss.technique.html_between_tags.new_tags_required] |
| **Quoted attribute** | no attacker byte may terminate the quoted value | only the matching `U+0022`; `" autofocus onfocus=... x="` executes with **zero** angle brackets | [xss.technique.html_attribute.new_event_handler_without_angle_brackets] [xss.evidence.attr_context.autofocus_onfocus_without_angle_brackets] |
| **URL attribute** | no attacker byte may control the *scheme* | the scheme terminator, not a quote — `javascript:` executes inside the attribute with no breakout at all | [xss.technique.html_attribute.href_javascript_pseudo_protocol] |
| **JavaScript string literal** | no attacker byte may escape the JS grammar **and** leave the remainder parseable | the string delimiter, plus syntax repair; a dangling fragment becomes a SyntaxError that kills the whole block | [xss.technique.js_string.break_out_and_repair_syntax] [xss.evidence.inside_a_quoted_javascript_string_literal_th] |
| **JavaScript template literal** | no attacker byte may supply an *evaluated* expression | the `${...}` grammar, which is evaluated during literal processing — nothing is broken, nothing is repaired | [xss.technique.template_literal.expression_without_terminator] |
| **Script block generally** | no attacker byte may close the element | the closing script sequence, because HTML parsing happens first | [xss.technique.js_script_tag.html_parsed_before_js] [xss.technique.ht_escaping_script_tag_if_your_co] |
| **No-execution context** | attribute value swallowed by the tokenizer | an unterminated attribute captures the rest of the response into a URL — data exfiltration with *no* script | [xss.technique.dangling_markup.exfiltrates_without_script_execution] |

## Why the "class name" framing is not an explanation

`xss` is not a filter-bypass class. The corpus's own framing is that proper output
encoding — not input filtering — is the control, and a keyword-level delete leaves the
brackets behind so the tag re-assembles
[xss.fp_rule.restricted_list_filter_that_deletes_a_keyword_leaves_a_live_payload]; the
explanation has to end at the parser and the invariant above. Anything that stops at
"the parameter is reflected" has completed one third of the chain; the second third is
whether those bytes can terminate their context
[xss.validation.encoding_must_match_landing_context], and the third is whether a
*different user* ever runs them
[xss.evidence.reject_a_reflected_xss_candidate_when_the_re].

Two non-obvious halves belong in the explanation because they change what "the
vulnerability" is:

- **DOM XSS has no server-side response at all.** The vulnerable code may never see
  the request; the same read of `location.hash` into `console.log` is not a finding,
  the same read into `innerHTML` is
  [xss.technique.dom.source_to_execution_sink] [xss.evidence.dom_based_xss_exists_only_where_an_attacker].
- **Content delivery decides execution, not payload bytes.** A JSON body reflected
  verbatim is not XSS until some HTML-typed or script-parsing surface consumes it
  [xss.technique.json_response.embedded_into_html_document].