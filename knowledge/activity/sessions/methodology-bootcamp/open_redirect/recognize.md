# recognize — the observations that justify investigating this class

A class name is not a signal. These are the things you actually SEE in traffic,
in a bundle, or in a proxy log that make open_redirect worth spending the hour.

## Primary signal — and its own exclusion

**The signal is user input reaching the redirect *destination*.** An open
redirect is only present when user-supplied input reaches the destination of a
redirect without validation, as distinct from any redirect that exists. A site
with forty redirects and no attacker-influenced destination has zero open
redirects [open_redirect.signal.user_input_reaches_redirect_destination].

The disproof on that signal is the recognition filter: if no supplied parameter
alters the `Location` host, or the destination is always a fixed internal route,
there is no open redirect to pursue
[open_redirect.signal.user_input_reaches_redirect_destination]. This is why
"reflected parameter" is not enough — see `reject_fp`.

## Where the parameter hides (highest-yield first)

1. **The login bounce.** When a site bounces the browser to a login prompt, the
   redirect parameter carried in that login URL — `next`, `retUrl` — *is* the
   post-login destination the user influences, so it is the parameter to fuzz.
   This is the single highest-yield observation in the class, and its disproof is
   equally concrete: the parameter refuses external hosts or ignores off-site
   values and always resolves to a fixed internal path
   [open_redirect.technique.hth_if_the_site_prompts_for_a_login].
2. **The authorize endpoint.** `redirect_uri` on an OAuth/OIDC authorize request
   is a destination parameter by definition, and it is where the impact ceiling
   of this class lives
   [open_redirect.chain_link.oauth_authorize_code_interception].
3. **Any 3xx on a GET.** The 3xx class of status code indicates that further
   action needs to be taken by the user agent in order to fulfil the request
   [open_redirect.evidence.automatic_redirection_needs_to_done_with_car]. Every
   such response is a candidate; the `Location` field is the carrier
   [open_redirect.evidence.if_a_location_header_field_section_7_1_2_is].
4. **`Content-Location` on a 2xx.** An absolute `Content-Location` naming a
   resource other than the requested one is the same class of trust decision
   reached by a different field
   [open_redirect.evidence.if_the_response_has_a_content_location_heade].
5. **The 303 "See Other" pattern.** Redirection to a different resource
   identified by the `Location` field, representing an indirect response, is the
   canonical post-action form
   [open_redirect.evidence.early_user_agents_split_on_whether_the_metho].
6. **The legacy status family.** In the HTTP/1.0 framing the whole 301/302 set is
   described as offering a choice of matching resources, each capable of
   representing the original request target
   [open_redirect.evidence.note_in_http_1_0_the_status_codes_301_moved] — i.e.
   the family is broad by design, so one status code does not localise the bug.

## Observation from the method side, not the bug side

The 3xx response is something you must be able to *observe*. Several corpus
items carry the same boundary: a candidate cannot be promoted on an observation
you cannot produce. A server receiving an `Expect` field-value other than
100-continue may answer 417
[open_redirect.evidence.a_100_continue_expectation_informs_recipient]; a 205
response must carry no payload
[open_redirect.evidence.since_the_205_status_code_implies_that_no_ad]; HEAD
responses terminate at the end of the header section, so no body is available to
read the `Location` out of
[open_redirect.evidence.a_payload_within_a_get_request_message_has_n]
[open_redirect.evidence.the_server_should_send_the_same_header_field]. These
matter practically: **do not validate with HEAD and do not validate through a
client that swallows 3xx** (see `validate`).

## The discriminating observation

The one observation that separates a reportable open redirect from padding is
the *post-authentication* hop: the unvalidated destination **after** login, not
before it, because the pre-auth redirect carries no session while the post-auth
one lands the user on the attacker's page already carrying a fresh session
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

Recognise that the corpus also names the exception, because a hunter who
applies the post-auth rule mechanically will discard a real pre-auth bug: the
pre-auth redirect is independently exploitable when it feeds a `Referer`-based
reset or a poisonable state parameter, or when the page performs an
authenticated action before redirecting
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

## What does NOT put this class on the board

- A 302 with no attacker-influenced parameter
  [open_redirect.signal.user_input_reaches_redirect_destination].
- A redirect parameter whose value must resolve to a path on the application's
  own origin: the finding requires the attacker to control the destination
  origin, not merely the path or the query string that follows the
  application's own host
  [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].
- An authorization server answering with a `redirect_uri_mismatch` error — that
  is the authorisation server's defence working
  [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].
