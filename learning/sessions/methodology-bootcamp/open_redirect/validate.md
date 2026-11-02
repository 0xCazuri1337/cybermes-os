# validate — the request/response pair that proves impact

## The proof bar

**An open redirect is proved by a 3xx response whose `Location` header resolves to
an attacker-controlled origin, captured with the redirect not followed.**
[open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter]

Two clauses, both load-bearing:

- **"whose `Location` header"** — the field is the carrier of the redirection.
  Redirection is the 3xx class of status code, indicating further action needs to
  be taken by the user agent in order to fulfil the request
  [open_redirect.evidence.automatic_redirection_needs_to_done_with_car], and the
  `Location` field is what identifies the different resource
  [open_redirect.evidence.if_a_location_header_field_section_7_1_2_is]
  [open_redirect.evidence.early_user_agents_split_on_whether_the_metho]. The
  301/302 family in the older framing covers a choice of matching resources, each
  capable of representing the original request target
  [open_redirect.evidence.note_in_http_1_0_the_status_codes_301_moved], so no
  single status code localises the bug.
- **"resolves to an attacker-controlled origin"** — parsed, not eyeballed. The
  same-origin rule's disproof lists exactly what makes the parsed authority differ
  from the raw string: userinfo tricks, backslash or tab/CR injection normalised
  into an authority, punycode/IDN homographs, an open redirector the app itself
  chains to, and relative paths a front-end router resolves against an
  attacker-controlled protocol or host. The instruction is to resolve the
  `Location` through a real browser parser before accepting it as same-origin
  [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**"captured with the redirect not followed"** — proof is the `Location` header of
an actual 302, not the presence of a URL parameter
[open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter]
[open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who].

## The request/response pair shape

```
GET /login?next=https%3A%2F%2Fyourhost.example%2Flanding HTTP/1.1
Host: app.example
Cookie: session=<authenticated session>

HTTP/1.1 302 Found
Location: https://yourhost.example/landing
```

Four properties make this a proof:

1. **A request-controlled parameter carries an external absolute URL.** User
   input reaches the destination of a redirect without validation
   [open_redirect.signal.user_input_reaches_redirect_destination].
2. **A 3xx is returned with `Location`.**
   [open_redirect.evidence.automatic_redirection_needs_to_done_with_car]
3. **The parsed authority of `Location` is `yourhost.example`, not `app.example`.**
   That is the invariant failing: the authority of the destination was chosen by
   the request, not by the application.
4. **The hop is post-authentication** (cookie present). The consequential
   open-redirect evidence is the post-authentication hop — the redirect that
   fires after a real login or token grant, not a bare redirect on an
   unauthenticated entry point, because the pre-auth redirect carries no session
   while the post-auth one lands the user on the attacker's page already carrying
   a fresh session
   [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

The corpus states the same bar for the mechanism side: an open redirect is
validated by reaching a controlled host through the parameter with the `Location`
header captured, not by the presence of a 302 alone
[open_redirect.validation.destination_allowlist_must_be_probed].

## Escalated proof shape — when the endpoint is OAuth

```
GET /authorize?client_id=<id>&response_type=code&scope=openid
    &redirect_uri=https%3A%2F%2Fyourhost.example%2Fcb HTTP/1.1
Host: app.example
Cookie: session=<authenticated session>

HTTP/1.1 302 Found
Location: https://yourhost.example/cb?code=<authorization code>&state=<state>
```

Same proof bar, and the code in the query is what makes it account compromise
rather than phishing: an open redirect on the OAuth authorize endpoint chains
into authorization-code theft when `redirect_uri` is accepted from user input
instead of an allowlist
[open_redirect.chain_link.oauth_authorize_code_interception]. The chain's own
disproof is the boundary — if the authorize endpoint rejects or ignores an
unregistered `redirect_uri` and the `Location` stays on an allowlisted origin,
the chain does not form and the finding is a normal post-login navigation
[open_redirect.chain_link.oauth_authorize_code_interception]. A
`redirect_uri_mismatch` answer means the authorisation server refused the
unregistered destination
[open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].

## What does NOT count as proof

| Not proof | Why | Anchor |
|---|---|---|
| A `next`/`returnUrl`/`redirect` parameter present on a request that returned 200 | The presence of a URL parameter proves nothing. | [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter] |
| A 302 with no attacker-influenced parameter | User input must reach the destination; the existence of a redirect is a distinct claim. | [open_redirect.signal.user_input_reaches_redirect_destination] |
| A screenshot of the page you landed on | Insufficient evidence — the `Location` must be captured from a raw exchange or the browser's network log. | [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter] |
| The same observation captured through a fetch-based client, a 3xx-rewriting proxy, or a redirect-following headless browser | The claim is false when the response cannot be observed with its headers intact; capture from a raw exchange instead. | [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter] |
| A response captured with HEAD | HEAD is identical to GET except the server MUST NOT send a body — the response terminates at the end of the header section, so there is no body to read a `Location` out of. | [open_redirect.evidence.a_payload_within_a_get_request_message_has_n] [open_redirect.evidence.the_server_should_send_the_same_header_field] |
| A same-host 302 with the parameter echoed into the URL | No request ever left the origin, so an attacker cannot place their page in the redirect chain. | corpus false-positive log; consistent with [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] |
| A redirect whose value resolves to a path on the application's own origin | The finding requires the attacker to control the destination origin, not merely the path or query string after the application's own host. | [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect] |
| A `redirect_uri_mismatch` error | The authorisation server refused the unregistered destination; that is its defence working. | [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect] |
| "The response was identical in every case" / the only evidence is server-side and not reflected | The test does not apply where the surrounding behaviour is unobservable. | [open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who] |

## What counts as proof of *bypass* rather than of *absence of validation*

A distinct and reportable outcome. When a controlled external host is refused as
a bare value but accepted once wrapped — as `//host`, as `https:/\host`, as
`https://app.example@host`, or as an unlisted host that simply is not on the
blocklist — the finding is real and the mechanism is specific: an
implementation that does a substring, suffix or `endsWith` test on the raw string
is defeated because such a value satisfies the substring test while resolving
elsewhere [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].
The report must say **which** invariant was broken — host termination, scheme
parsing, or the scheme allowlist — because a remediation for one does not close
the others, and a check that also rejects relative and scheme-relative input
closes the remaining variants
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

## Recording requirement

The evidence must be an artifact a reviewer can re-check, not a claim the hunter
asserts — a hunter must be able to state the concrete observation that
demonstrates it, with a request and response in hand, before the finding is
reportable [open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who].
Store: raw request, raw response with headers intact, redirect-following
disabled, the parsed authority of the `Location`, and the session state at the
time. Anything less is an assertion
[open_redirect.evidence.automatic_redirection_needs_to_done_with_car]
[open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who].
