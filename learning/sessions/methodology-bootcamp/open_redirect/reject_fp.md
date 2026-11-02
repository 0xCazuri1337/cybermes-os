# reject_fp — the misleading cases, with the disproof test for each

Every rule below carries its own disproof. A rule without a disproof test is a
habit, not a filter. The disproof column is the thing you must run **before**
rejecting — because three of these four rules are conditional.

---

## FP-1 — Redirect to a relative path, the same host, or a subdomain of the same
registrable domain

**The claim.** A 301/302 whose `Location` is a relative path, a protocol-relative
same-origin path, or an absolute URL whose authority equals the request `Host` is
not an open redirect: the browser cannot be moved off the origin, so there is no
phishing pivot and no token or credential leakage to a foreign authority
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

The same boundary, stated from the other side: a redirect parameter whose value
must resolve to a path on the application's own origin is not an open redirect,
because the finding requires the attacker to control the **destination origin**,
not merely the path or the query string that follows the application's own host
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

**Disproof test (run before rejecting).** Resolve the `Location` through a real
browser parser — the rule's own instruction — and check whether the authority
differs after full parsing. The redirect **IS** open if:

- userinfo tricks put an attacker host in the userinfo field;
- backslash or tab/CR injection is normalised by the browser into an authority;
- the host is a punycode/IDN homograph;
- the app itself chains to an open redirector;
- a relative path is resolved by a front-end router against an
  attacker-controlled protocol or host
  [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Test that must be applied alongside:** a redirect parameter whose value must
resolve to a path on the application's own origin
[open_redirect.test.a_redirect_parameter_whose_value_must_resolve_to] — noting
that the rule is scoped to **server-side** resolution. It is wrong when the value
is resolved by a client instead: a protocol-relative value, a
scheme-relative or backslash-normalised form, or a value a downstream client
(email client, chat renderer, mobile deep-link handler) reinterprets as absolute
— because the server-side check passes while the user agent still leaves the
origin [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

**Corpus false-positive log for this case.** An endpoint reflects a redirect
parameter into the `Location` header, therefore it is an open redirect —
invalidated because the 302 pointed back at the same host with the parameter
echoed into the URL; no request ever left the origin, so an attacker cannot place
their page in the redirect chain. The rejection rule: a reflected redirect
parameter is not an open redirect; resolve the `Location` and confirm the 3xx
leaves the origin, because a same-host 302 with the parameter echoed is not a
finding and "reflected parameter" alone will be read as padding on review.

**On subdomains specifically (scoped note, stated as reasoning and not as a
corpus claim):** the corpus rules as written cover "relative path", "same
origin", and "authority equals the request `Host`"
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] and
"path on the application's own origin"
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect];
neither states a registrable-domain exemption in so many words. Treat a
subdomain-of-the-same-site `Location` as a **triage decision, not an automatic
reject**: parse it, establish that the registrable domain matches, then confirm
the subdomain cannot itself be attacker-takeoverable. If you cannot rule that
out, it does not pass the rule and stays in scope.

---

## FP-2 — The parameter IS validated, but only against a list of known-bad hosts

**This is the dominant mechanism mis-report, and the error it produces is worse
than a false negative.** A blocklist is a **real finding with a different
mechanism**: *blocklist bypass*, not *missing validation*. It must never be
reported as "no validation". Two reasons that matters:

1. **Remediation.** "Add an allowlist" and "replace the blocklist with an
   allowlist" are different tickets, and a reviewer who reads "no validation"
   cannot tell which defect is present.
2. **Mechanism accuracy.** The corpus's bypass family for this class is precisely
   about defences that inspect the destination without parsing it: an
   implementation that does a substring, suffix or `endsWith` test on the raw
   string is defeated because a value whose name merely contains the allowed
   host, or one carrying an allowed host behind a credential-holding prefix,
   satisfies the substring test while resolving elsewhere
   [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].
   A blocklist and a naive substring test are the same kind of defect.

**The test that decides it** [open_redirect.test.an_open_redirect_defence_that_inspects_the_desti]:
probe a destination that is **not on the blocklist and not obviously malicious** —
an unregistered, unused, plain-name host you control or will control. If it is
accepted, the finding is *blocklist bypass*, and the evidence is that single
accepted non-listed host [open_redirect.validation.destination_allowlist_must_be_probed].

**The test that exonerates it.** The bypass claim is false when the check parses
with a WHATWG-compatible URL constructor and compares the parsed host for exact
equality, because the confusable forms then fail to match and no substring
confusion is possible; a check that also rejects relative and scheme-relative
input closes the remaining variants
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

**Disqualifier carried by the test itself:** it does not apply where the
surrounding behaviour is unobservable — when the response is identical in every
case, or the only evidence is server-side and not reflected to the requester
[open_redirect.test.an_open_redirect_defence_that_inspects_the_desti].

---

## FP-3 — The redirect is a third party's registered `redirect_uri`, or the
server answered `redirect_uri_mismatch`

**Claim A.** A tenant's OAuth authorize endpoint redirecting to an arbitrary
external origin is the third-party application's registered `redirect_uri`, not an
open redirect in the tenant's own web application
[open_redirect.fp_rule.registered_oauth_redirect_uri_is_not_a_webapp_open_redirect].

**Disproof test for A:** the arbitrary external destination is reachable with a
**client id the tenant never registered**, or with a **registered** client id
whose `redirect_uri` is fixed to the application's own origin — which shows the
redirection value is attacker-supplied in the request rather than tenant-configured
[open_redirect.fp_rule.registered_oauth_redirect_uri_is_not_a_webapp_open_redirect].
Any of those two results flips it to a finding.

**Claim B.** An authorization server answering with a `redirect_uri_mismatch`
error has refused the unregistered destination, so that exchange is the
authorisation server's defence working and must not be reported as an open
redirect on the client
[open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].
The corresponding test item
[open_redirect.test.an_authorization_server_answering_with_a_redirec] carries the
standard disqualifier: it does not apply where the surrounding behaviour is
unobservable [open_redirect.test.an_authorization_server_answering_with_a_redirec].

**Disproof test for B — two distinct escapes:** the rule is wrong when

- **the client is at fault** — it holds a pre-registered wildcard or prefix
  pattern that the server honours, so an attacker's host matches a registered
  pattern and the code is returned to it; or
- **the mismatch was only for the tested variant** while a weaker registered form
  still accepts the malicious origin, in which case the server's exact-match rule
  is not what stopped the attack
  [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].

Both escapes must be attempted before the OAuth finding is closed. A single
`redirect_uri_mismatch` on one payload shape proves the server rejected *that
shape*, not that the flow is safe.

---

## FP-4 — "The parameter refused external hosts, so there is no finding"

**The claim being tested.** The login-bounce signal's own disproof: the redirect
parameter refuses external hosts or ignores off-site values and always resolves
to a fixed internal path
[open_redirect.technique.hth_if_the_site_prompts_for_a_login].

**Why this is a false-positive trap rather than a fact.** The signal item states
the general boundary — if no supplied parameter alters the `Location` host, or
the destination is always a fixed internal route, there is no open redirect to
pursue
[open_redirect.signal.user_input_reaches_redirect_destination] — but a refusal
observed on **one** value shape does not establish a refusal on all shapes. The
allowlist-defence items give the exact reason a naive refusal test can be wrong:
substring, suffix and `endsWith` implementations are defeated by confusable and
userinfo-laden values
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host],
and the same-origin rule's disproof lists the normalisation routes that leave the
origin despite a passing server-side check
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Disproof test:** run the scheme-family sweep before closing — protocol-relative,
backslash-normalised, userinfo-confused, and one non-blocklisted host
[open_redirect.validation.destination_allowlist_must_be_probed]. Only a refusal
that holds across all of them, resolved through a real browser parser, supports
the rejection.

---

## Rejection discipline

A rejection is only written down when three things are on record: the
**observed** `Location`, the **parsed** authority, and the **variant set** tried.
"Reflected parameter alone will be read as padding on review" is the corpus's own
warning, and padding is what gets a report closed as a duplicate of every other
open-redirect report in the queue
[open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter]
[open_redirect.signal.user_input_reaches_redirect_destination].
