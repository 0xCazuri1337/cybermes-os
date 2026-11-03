# validate — the request/response pair that proves impact, and what does not count

## The proof shape

A validated XSS finding is **two** request/response pairs plus one browser
observation, not one screenshot of a popup.

**Pair 1 — the entry point (reflection / storage).** The exact request carrying the
unique marker, and the response showing the marker verbatim at a named offset in a
browser-parsed context. Record every offset: one parameter often reflects twice
[xss.test.entrypoints.unique_alnum_marker_sweep].

**Pair 2 — the context and the sink.** The same request re-sent with the
context-appropriate payload, and the response showing the injected markup in the sink
position. For stored XSS, pair 2 is a **different session's** request to the exit
page [xss.test.stored.two_identity_entry_to_exit_point_link].

**Browser observation — actual execution.** The exact saved request replayed into a
real browser, keeping every cookie and header, with a payload that produces an
unambiguous side effect: `alert(document.domain)` names the origin it ran in, and
`document.title='XSS-PROOF'` or a body overwrite survives blocked popups
[xss.test.execution.confirm_in_real_browser].

**Pair 3 — impact (reportability).** A same-origin request issued *from* the injected
script to an endpoint the victim can reach, with the authenticated response body and
the resulting state change visible on a second page load
[xss.chain_link.same_origin_authority.victim_session_actions]. The cookie is attached
by the browser regardless of `HttpOnly`, and `SameSite` is evaluated against the
request's site context, so a script on the target origin is same-site
[xss.chain_link.cookie_posture.httponly_and_samesite_do_not_block_same_origin_script].
An anti-CSRF token is no barrier either — read it out of the page and replay
[xss.chain_link.csrf_token_read_defeats_csrf_defence]. Read the header verbatim and
report it alongside the pair, because the CSP verdict is per-response
[xss.evidence.a_reflected_xss_on_a_page_whose_csp_is_nonce].

## What does NOT count as proof

- **A payload visible in a response pane.** Unexecuted source text.
- **An alert in your own session only.** That is Observation A — it proves the sink,
  not a reportable vulnerability, because impact requires reaching another user's
  session or a reachable victim path
  [xss.validation.self_fired_marker_is_not_a_reportable_finding]. A popup is a proof
  mechanism, not the vulnerability.
- **"The input is reflected" with the location expected.** Reflection plus an
  entity-encoded value is still not XSS
  [xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context]
  [xss.evidence.reject_a_reflected_xss_candidate_when_the_re].
- **Persistence in your own reload.** Proves storage, not cross-user execution
  [xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view]
  [xss.evidence.reject_a_stored_xss_candidate_when_the_submi].
- **A marker firing in the submitter's own address bar or console.** Self-XSS; nothing
  crosses a user boundary [xss.fp_rule.self_xss.payload_renders_only_in_submitter_browser].
- **A `document.cookie` exfiltration payload on an HttpOnly session.** Cannot work;
  rescope to in-origin action instead
  [xss.bypass.trusted_types.dom_sink_requires_policy] for the enforcement-side check
  and read `HttpOnly` before writing the impact line.
- **Grep hits for `innerHTML` in a bundle.** A candidate list, not a vulnerability —
  dead code, comments and minifier artifacts all produce hits
  [xss.test.dom.enumerate_dangerous_sinks_in_bundle].
- **"It is behind HTTPS."** Irrelevant: an origin is scheme+host+port, so same-origin
  execution inside the HTTPS origin is unaffected
  [xss.impact.transport_security.tls_does_not_mitigate_same_origin_execution].
- **Score inflation from page sensitivity alone.** On an authenticated page the
  injected script inherits privileged in-origin actions and the finding is materially
  higher; on an anonymous page the ceiling is what an anonymous session may reach
  [xss.impact.authenticated_reflected_beats_anonymous_page]
  [xss.fp_rule.readonly_brochureware_page_does_not_clear_xss].
- **A `postMessage` listener existing.** The finding is a receiver that acts on
  `e.data` without an origin allow-list
  [xss.technique.postmessage.receiver_must_validate_event_origin]
  [xss.evidence.postmessage.origin_check_must_be_allowlist_on_receiver]; sender-side
  `targetOrigin` is about delivery and is not a substitute, since the target origin
  can change after the send.
- **A service-worker claim without both prerequisites.** You need attacker-controlled
  JS served *from the target origin* (upload or JSONP whose callback can be broken out
  of) *and* an XSS that registers the worker
  [xss.prerequisite.ht_attack_creating_a_service_worker]
  [xss.prerequisite.ht_this_is_the_code_that_must_be_uplo].
  Persistence claims must also survive the update-check window
  [xss.impact.ht_for_example_javascript_var_sw].