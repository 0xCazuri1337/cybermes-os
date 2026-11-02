# chain — prerequisites, transition, escalation, blocker at each step

Each row states the prerequisite that must hold, the transition that moves the chain,
and the **blocker** that stops it — named so I can test the blocker rather than assume
it.

## Chain A — reflected XSS to victim-authority actions (the default escalation)

| Step | Prerequisite | Transition | Blocker |
|---|---|---|---|
| A0 | A request-controlled surface | Send a unique marker; it must reappear in the same immediate response | No reflection in the immediate response → drop the candidate [xss.prereq.reflected.request_data_in_immediate_response] |
| A1 | Marker in a browser-parsed context | Name the context; pick the matching payload family | Wrong context → miss; the miss is a context error, not safety [xss.test.context.determine_injection_context] |
| A2 | Unneutralised output | Payload executes in a real browser | CSP nonce/hash without `unsafe-inline` [xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload]; Trusted Types with no default policy — the sink throws [xss.evidence.trusted_types.sink_throws_when_no_default_policy_returns_trustedscript] |
| A3 | Execution proven | Victim must be reachable: a link they click, or a value they submit | Self-XSS — delivery requires the victim to paste into their own console [xss.fp_rule.self_xss.payload_renders_only_in_submitter_browser]; marker fires only in the hunter's own session [xss.validation.self_fired_marker_is_not_a_reportable_finding] |
| A4 | Script runs in the victim's origin | Issue a same-origin request to an endpoint the victim can reach; observe the authenticated response and the state change | The same-origin request comes back unauthenticated / identical to anonymous → the script is not carrying victim authority, and the claimed ceiling does not apply [xss.chain_link.same_origin_authority.victim_session_actions] |
| A5 | Victim authority confirmed | Escalate: read an admin-only page or call an admin-only endpoint | No admin surface reachable from that session → impact ceiling is the victim's own account authority [xss.chain_link.same_origin_authority.victim_session_actions] |
| A6 | Same-origin actions blocked by defence layers? | Read the CSRF token out of the page, replay the request with it | The endpoint refuses even with the correctly-read token → the defence holds for that endpoint [xss.chain_link.csrf_token_read_defeats_csrf_defence]. Cookies are attached regardless of `HttpOnly`/`SameSite` [xss.chain_link.cookie_posture.httponly_and_samesite_do_not_block_same_origin_script] |
| A7 | Full takeover path | Change the account email from injected script, then run the ordinary password-reset flow for the new address | The email-change endpoint re-authenticates or re-sends the password, or reset mail still goes only to the original address [xss.chain_link.email_change_then_password_reset_takes_over_account] |

## Chain B — self-XSS to administrator compromise (stored)

| Step | Prerequisite | Transition | Blocker |
|---|---|---|---|
| B0 | A low-privilege stored field (name, comment, bio, ticket text) | Store the payload as identity A; confirm it persists unescaped | The value is overwritten before any second read (ephemeral carts, recent-searches lists) → re-read after an unrelated action before claiming durability [xss.test.stored.two_identity_entry_to_exit_point_link] |
| B1 | Persistence | Authenticate as identity B with strictly greater privilege; open the view rendering A's data | **Never demonstrate this with the submitter's own session** — the payload never renders for a second user → it is self-XSS [xss.chain_link.stored_payload_reaching_an_administrator_view] |
| B2 | Payload fires in B's session | Read an admin-only page or call an admin-only endpoint | The marker fires for the author only; a per-role rendering difference means your own view can look safe while the admin view is exploitable [xss.chain_link.stored_payload_reaching_an_administrator_view] [xss.test.stored.two_identity_entry_to_exit_point_link] |
| B3 | Privileged response obtained | Continue up Chain A from step A4 with B's authority | Blocker: the privileged response is the proof, not the marker firing |

## Chain C — pollution/clobber primitive to execution

| Step | Prerequisite | Transition | Blocker |
|---|---|---|---|
| C0 | A recursive object merge that accepts `__proto__` keys | Send `__proto__[transport_url]=//evil.example.com` | The merge rejects/ignores `__proto__` and `constructor`, or `Object.prototype` is frozen/sealed → nothing is inherited [xss.chain_link.prototype_pollution_to_dom_xss] [xss.evidence.prototype_pollution.transport_url_gadget_reaches_script_src] |
| C1 | Property written to the prototype | Find a gadget: code that reads a missing option/tag allowlist/callback/URL and writes it into a sink | Config object defines its **own** property → own property beats the prototype; a null-prototype object → nothing inherited; the library only builds a URL for display and never assigns it to a fetching property [xss.evidence.prototype_pollution.transport_url_gadget_reaches_script_src] |
| C2 | Value lands in `innerHTML`/`document.write`/`script.src`/`eval` | Script execution with an injection-only primitive | CSP restricts `script-src` to the origin → the chain stops at the network request, not execution [xss.evidence.prototype_pollution.transport_url_gadget_reaches_script_src] |
| C0' | Injected markup with `id`/`name` | Named element shadows a `window`/`document` property read as a config object | Page never reads the clobbered property; the code uses `getElementById` or a scoped lookup [xss.technique.dom_clobbering.named_element_shadows_configuration_object]; property only read into `textContent`/attribute/URL fetch [xss.fp_rule.dom_clobbering.property_read_into_safe_sink] |

## Chain D — cross-origin message to sink

| Step | Prerequisite | Transition | Blocker |
|---|---|---|---|
| D0 | A page with a `message` listener | Post from an attacker-controlled origin | Handler validates `e.origin` against an exact allow-list before acting → rejected [xss.technique.postmessage.receiver_must_validate_event_origin] |
| D1 | No origin check, or a check that trusts a same-origin-looking sender | Handler assigns `e.data` into `innerHTML` | Handler writes through a text-only assignment, or the written content executes no script/handlers [xss.technique.hth_example_of_an_insecure_implementat] |
| D2 | Sink reachable with attacker-chosen data | Execution in the receiving origin | The sender-side `targetOrigin` is **not** a substitute for the receiver check — the target window's origin can change after the send via redirect [xss.evidence.postmessage.origin_check_must_be_allowlist_on_receiver] |

## Chain E — persistence (service worker)

| Step | Prerequisite | Transition | Blocker |
|---|---|---|---|
| E0 | A place to serve attacker JS **from the target origin** — file upload or a JSONP endpoint whose callback can be filled with arbitrary JS | XSS registers and installs the worker | No arbitrary-JS hosting on the origin and no breakable JSONP → the prerequisite fails [xss.prerequisite.ht_attack_creating_a_service_worker] |
| E1 | Worker served from the target origin, `fetch` listener forwards intercepted URLs off-origin | Every intercepted request is exfiltrated | Worker served off-origin, or the JSONP response cannot be broken out of [xss.prerequisite.ht_this_is_the_code_that_must_be_uplo] |
| E2 | Worker installed | Persistence claim | Persistence outlives the 24-hour cache-bypass window on update checks; "fixed within a day" is unsupported until a changed script is fetched, installed and activated [xss.impact.ht_for_example_javascript_var_sw] |