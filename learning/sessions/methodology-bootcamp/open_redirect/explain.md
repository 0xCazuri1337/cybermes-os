# explain — open redirect from first principles

## The chain, end to end

An open-redirect report is a claim about an **authority decision**, not about a
URL. Seven links, and a hunt dies at any of them:

1. **attacker input** — a request-controlled parameter that names a destination:
   `next`, `retUrl`, `returnUrl`, `redirect`, `continue`, `target`, `dest`, or
   `redirect_uri`. The class exists only when user-supplied input reaches the
   *destination* of a redirect; the mere existence of a redirect is a different
   claim entirely [open_redirect.signal.user_input_reaches_redirect_destination].
2. **parser** — the URL parser of whichever component ultimately dereferences the
   value. The server may parse it one way, the user agent another, and the
   authority is decided by the *last* parser in the chain, not the first.
3. **normalisation** — percent-decoding, backslash-to-slash folding, tab/CR
   removal, scheme case-folding, IDN/punycode mapping. Each of these is a place
   where the raw string and the parsed authority diverge.
4. **validation** — an allowlist, a prefix test, a substring test, or a blocklist
   of known-bad hosts. Each is a different mechanism with a different failure
   mode, and conflating them produces a wrong report (see `reject_fp`).
5. **trust decision** — the application emits a `Location` whose authority it did
   not choose, on the strength of its own origin. Trust is inherited from the
   origin, not earned by the destination
   [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].
6. **internal operation** — a 3xx whose `Location` field redirects the user agent
   to a different resource
   [open_redirect.evidence.automatic_redirection_needs_to_done_with_car]
   [open_redirect.evidence.early_user_agents_split_on_whether_the_metho], or a
   `Content-Location` naming a different resource
   [open_redirect.evidence.if_the_response_has_a_content_location_heade]. The 3xx
   class is precisely "further action needs to be taken by the user agent in
   order to fulfil the request" [open_redirect.evidence.automatic_redirection_needs_to_done_with_car],
   and `Location` is the field that carries it
   [open_redirect.evidence.if_a_location_header_field_section_7_1_2_is]. 301 and 302
   in HTTP/1.0-era framing cover the whole family of "matching resources capable
   of representing the original request target"
   [open_redirect.evidence.note_in_http_1_0_the_status_codes_301_moved].
7. **observable result** — the victim leaves the origin. Nothing else counts.

## The exact invariant that fails

**The authority of a redirect destination emitted by this application must be an
authority the application chose, not one the request chose.** Everything
downstream — phishing credibility, `Referer` leakage of the authenticated URL,
token or code in the query string — is consequence, not definition.

That invariant does not fail once. It fails in **three structurally different
places**, one per scheme family, and a hunter who tests only one of them will
report "not vulnerable" on a live bug:

| Scheme family | Payload shape | Which link breaks | Why the usual defence misses it |
|---|---|---|---|
| **Protocol-relative** | `//evil.example/p` | **Host termination** | No scheme is present at all, so a scheme allowlist or a `startsWith("https://app")` test never evaluates. The authority begins at `//` and the host is `evil.example`. The value still looks "relative" to any checker that tests for a leading `/` [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open]. |
| **Backslash-normalised absolute** | `https:/\evil.example`, `https:\\evil.example` | **Scheme parsing / normalisation** | The string begins with the app's own scheme, so a prefix test passes; the browser's parser then folds the backslash into a path separator and reads `evil.example` as the authority [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open]. |
| **Dangerous scheme** | `javascript:...`, `data:...` | **The scheme allowlist itself** | There is no host to validate at all. A check of the form "is the host mine?" has nothing to inspect, so it returns vacuously true or is skipped entirely [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host]. |

Two further ways the same invariant breaks, both of which are *parser* failures
rather than validation failures:

- **Userinfo confusion.** `https://app.example@evil.example/` contains the allowed
  host as the userinfo field. Any substring or `contains` test on the raw string
  passes; the parsed authority is `evil.example`
  [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].
- **Confusable host.** A hostname that merely *contains* or *ends with* the
  allowed host satisfies an `endsWith`/substring implementation while resolving
  somewhere else. The corpus is explicit: only a real WHATWG-compatible URL
  constructor plus exact host equality defeats this, and a check that also
  rejects relative and scheme-relative input closes the rest
  [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

## The boundary the corpus draws, and where it sits in the chain

An open redirect requires the attacker to control the **destination origin**,
not the path or the query string that follows the application's own host
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].
A relative path, a protocol-relative same-origin path, or an absolute URL whose
authority equals the request `Host` cannot move the browser off the origin, so
there is no phishing pivot and no credential or token leakage to a foreign
authority [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

That boundary is why the disproof on the same-origin rule is long: it is open if
the authority differs *after full parsing* — userinfo tricks, backslash or
tab/CR injection that browsers normalise into an authority, punycode/IDN
homographs, an open redirector the app itself chains to, or a relative path a
front-end router resolves against an attacker-controlled protocol or host. The
rule's own instruction is to resolve the `Location` through a real browser parser
before accepting it as same-origin
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

## Consequence is not definition

A redirect that is *not* an open redirect on its own becomes one when it feeds
something. The corpus draws the sharpest version of that line around
authentication: the consequential open-redirect evidence is the
**post-authentication** hop — the redirect that fires after a real login or token
grant — not a bare redirect on an unauthenticated entry point, because the
pre-auth hop carries no session while the post-auth one lands the user on the
attacker's page already holding a fresh session
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].
The disproof matters as much: the pre-auth redirect is independently exploitable
when it feeds a `Referer`-based reset or a poisonable state parameter, or when
the page performs an authenticated action before redirecting.

The consequence taxonomy this class must be triaged into:

- **Credential phishing.** A trusted-origin URL that lands on an attacker page
  carrying a fresh session
  [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].
- **Referer / URL leakage.** Sensitive query material in the pre-auth hop that
  the redirect forwards.
- **Authorization-code theft.** A different impact entirely: an open redirect on
  the OAuth authorize endpoint chains into code interception when `redirect_uri`
  is accepted from user input instead of an allowlist
  [open_redirect.chain_link.oauth_authorize_code_interception]. This is the
  centrepiece of `chain`, and it converts a phishing-grade finding into an
  account-compromise one.

That last row is the reason this class cannot be triaged on "does it leave the
origin" alone. Leaving the origin is the *definition*; what the destination
receives is the *severity*.
