# failure_analysis — expected vs actual vs wrong assumption vs next test

A real failure mode of this class, decomposed. The failure is the one that kills
the most open-redirect work: **the report looked correct and was wrong about the
mechanism and about severity, in that order.**

---

## The failure

**Expected.** An endpoint reflected a `next` parameter into the `Location` of a
302 and would not accept an external host on a direct probe. On that evidence the
expected outcome was a closed ticket: "redirect parameter present but destination
validated", which is the signal's own exclusion — if no supplied parameter alters
the `Location` host, or the destination is always a fixed internal route, there
is no open redirect to pursue
[open_redirect.signal.user_input_reaches_redirect_destination].

**Actual.** Two of the three refused probes were the wrong *shape*, not the right
refusal:

- `https://evil.example/` was refused, so the naive write-up was "no open
  redirect".
- `//evil.example/` was **accepted** and returned a 302 whose `Location` the
  browser resolved to `https://evil.example/`. No scheme was ever present, so the
  scheme/prefix check never evaluated — the value still looked like a relative
  path to any string test
  [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].
- `https:/\evil.example` was likewise **accepted**: the string begins with the
  app's own scheme, passes the prefix test, and is only later folded into a
  different authority by the parser
  [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

Worse, the endpoint sat behind authentication and the redirect fired **after**
login, which is the hop the corpus names as the consequential one — the post-auth
redirect lands the user on the attacker's page already carrying a fresh session
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].
So the ticket, as written, understated both existence and severity.

**Wrong assumptions, named.**

1. **"A refusal on one absolute-URL shape is a refusal on all shapes."** The
   defence's failure modes are structural, not cosmetic: an implementation that
   does a substring, suffix or `endsWith` test on the raw string is defeated by a
   value whose name merely contains the allowed host, or by an allowed host
   behind a credential-holding prefix, because those satisfy the substring test
   while resolving elsewhere
   [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].
   One shape proves nothing about the parser.
2. **"The string I sent is the URL that was used."** This is the assumption the
   same-origin rule exists to forbid: the redirect IS open if the authority
   differs after full parsing — userinfo tricks, backslash or tab/CR injection
   normalised into an authority, punycode/IDN homographs, an open redirector the
   app chains to, or a relative path a front-end router resolves against an
   attacker-controlled protocol or host. The rule's own instruction is to resolve
   the `Location` through a real browser parser before accepting it as
   same-origin [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].
   I had skipped the resolve step and compared raw strings — the same defect I
   was about to report in the target.
3. **"It starts with `/`, so it is a relative path and therefore safe."** This is
   the dominant false positive in this class, in two wordings: a relative path, a
   protocol-relative same-origin path, or an absolute URL whose authority equals
   the request `Host` is not an open redirect
   [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] —
   but that rule's disproof lists exactly the normalisation routes that make a
   leading-slash value leave the origin. The rule is a conclusion reached by
   parsing, not a conclusion reached by reading the first character.
4. **"The parameter is refused, so the app validates, so this is a hygiene nit."**
   The inverse error, and the more damaging one for the program: the app *does*
   validate, badly — which makes it a **blocklist/bypass finding with a real
   remediation**, not a "no validation" finding. Misnaming it sends the fix team
   to the wrong control
   [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host]
   [open_redirect.validation.destination_allowlist_must_be_probed].
5. **"It requires authentication, so an anonymous probe showing nothing proves
   nothing is there."** Inverted as well: the session-gated hop is the
   high-impact one, and its absence from an anonymous crawl is a gap in the scan,
   not a negative result
   [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

**Next tests, in order.**

1. Re-run the full scheme-family sweep — protocol-relative, backslash-normalised,
   userinfo-confused, dangerous scheme, and one **non-blocklisted, plain-name
   host** — because an open redirect is validated by reaching a controlled host
   through the parameter with the `Location` header captured, not by the presence
   of a 302 alone [open_redirect.validation.destination_allowlist_must_be_probed].
   The non-listed plain-name host is the probe that separates "blocklist bypass"
   from "no defence", and it is the probe I never ran.
2. Capture every `Location` with the redirect **not followed**, from a raw
   exchange: proof is the `Location` header of an actual 302, and the claim is
   false when the response cannot be observed with its headers intact — a
   fetch-based client, a proxy that rewrites 3xx, or a headless browser
   configured to follow redirects — in which case a screenshot of the final page
   is insufficient evidence
   [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter].
   Never validate with HEAD: the response terminates at the end of the header
   section, so there is no body to read a destination out of
   [open_redirect.evidence.a_payload_within_a_get_request_message_has_n]
   [open_redirect.evidence.the_server_should_send_the_same_header_field].
3. Resolve each captured `Location` with a WHATWG-compatible parser and compare
   the **parsed host** to the request `Host`
   [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].
4. Test with an authenticated session and record the session state, because the
   post-authentication hop is the one whose consequence is a fresh session landing
   on the attacker's page
   [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it]
   — and check the pre-auth exception explicitly rather than assuming it away: a
   pre-auth redirect is independently exploitable when it feeds a
   `Referer`-based reset or a poisonable state parameter, or when the page acts
   before redirecting
   [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].
5. Rewrite the mechanism line to name **which** invariant broke — host
   termination, scheme parsing under normalisation, or the scheme allowlist —
   since that is what determines whether a partial fix holds
   [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].
6. If the endpoint turned out to be an authorize endpoint, run the OAuth
   registration tests: an authorization server answering with a
   `redirect_uri_mismatch` error has refused the unregistered destination and must
   not be reported as an open redirect on the client — but the rule is wrong when
   the client holds a pre-registered wildcard or prefix pattern the server
   honours, or when a weaker registered form still accepts the malicious origin
   [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect]
   [open_redirect.test.an_authorization_server_answering_with_a_redirec].

---

## Second failure mode — the report that was right and unprovable

**Expected.** A raw request/response pair showing the off-origin `Location`.

**Actual.** The capture was taken through a tool that followed the redirect, so
only the final 200 page was on record.

**Wrong assumption.** That reaching the attacker page was itself proof. It is
not: proof is the `Location` header of an actual 302, captured with the redirect
not followed, and a screenshot of the final page is insufficient evidence
[open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter]
[open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who].

**Next test.** Re-capture with redirect-following disabled, store raw request and
raw response with headers intact, and state the parsed authority. Record the
observation as an artifact a reviewer can re-check, not as a claim asserted —
and note the standing disqualifier on every test in this class: it does not apply
where the surrounding behaviour is unobservable, when the response is identical in
every case, or when the only evidence is server-side and not reflected to the
requester [open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who]
[open_redirect.test.an_open_redirect_defence_that_inspects_the_desti]
[open_redirect.test.a_redirect_parameter_whose_value_must_resolve_to]
[open_redirect.test.an_authorization_server_answering_with_a_redirec].

---

## The transferable lesson

This class is a lesson about **where in the chain the parse happens**. Every
false rejection above came from reading the raw string; every real finding came
from resolving the value and comparing authorities. The same discipline applies
to the defence side, because the target's own bug and my analytical bug were the
same bug: a comparison performed on text instead of on a parsed authority
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host]
[open_redirect.signal.user_input_reaches_redirect_destination].
