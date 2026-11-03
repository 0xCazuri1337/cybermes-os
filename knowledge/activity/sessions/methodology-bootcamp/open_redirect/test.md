# test — ordered plan with expected information gain per step

The corpus is explicit about the bar a test must clear: a hunter must be able to
state the concrete observation that demonstrates the case, with a request and a
response in hand, before the finding is reportable
[open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who]. And every
test below inherits the same disqualifier: it does not apply where the
surrounding behaviour is unobservable — for example when the response is
identical in every case, or when the only evidence is server-side and not
reflected to the requester [open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who].

Each step therefore carries an explicit expected information gain, phrased as the
branch it eliminates.

---

## Step 0 — Fix the observation channel (do this first; it invalidates everything after)

**Action:** confirm you can read the `Location` header of a 3xx without following
the redirect — raw exchange, proxy with redirect-following off, or a browser
network log.

**Why first:** the proof is a 3xx response whose `Location` header resolves to an
attacker-controlled origin, captured with the redirect *not* followed
[open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter].
The claim is false when the response cannot be observed with its headers intact —
a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured
to follow redirects — in which case the `Location` must be captured from a raw
exchange or the browser's network log, and a screenshot of the final page is
insufficient evidence [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter].

**Do not use HEAD.** A HEAD response terminates at the end of the header section,
so there is no body to read a destination out of
[open_redirect.evidence.a_payload_within_a_get_request_message_has_n]
[open_redirect.evidence.the_server_should_send_the_same_header_field].

**Information gain:** eliminates the entire class of false negatives caused by an
invisible `Location`. Zero technical information, maximal methodological value.

---

## Step 1 — Baseline: does any supplied parameter alter the `Location` host?

**Action:** request the endpoint with the candidate parameter absent, then with a
value that is unambiguously external and controlled by you. Capture both
`Location` headers.

**Decision rule:** an open redirect is validated by reaching a controlled host
through the parameter with the `Location` header captured, **not** by the
presence of a 302 alone [open_redirect.validation.destination_allowlist_must_be_probed].

**Information gain:** splits the whole hunt into "the parameter is not
user-controllable — stop" and "the parameter is user-controllable — everything
downstream is about mechanism". This is the highest-yield single request in the
class, and the corpus's invalidation condition is explicit: if the controlled
host never appears in any `Location` across absolute, relative and near-miss
variants, the redirect is not user-controllable and validation fails
[open_redirect.validation.destination_allowlist_must_be_probed].

---

## Step 2 — Negative control: is the destination always a fixed internal route?

**Action:** vary the parameter across obviously-internal values and confirm the
`Location` is invariant.

**Information gain:** this is the corpus's own false-positive boundary — a 302
that pointed back at the same host with the parameter echoed into the URL, where
no request ever left the origin, cannot place an attacker's page in the redirect
chain. A same-host 302 with the parameter echoed is not a finding.

---

## Step 3 — Resolve the destination through a real parser, never by string inspection

**Action:** parse the observed `Location` with a WHATWG-compatible URL
constructor and compare the *parsed host* to the request `Host`.

**Why this is its own step:** the same-origin rule's disproof is that the redirect
IS open if the authority differs after full parsing — userinfo tricks, backslash
or tab/CR injection normalised into an authority, punycode/IDN homographs, an
open redirector the app itself chains to, or a relative path a front-end router
resolves against an attacker-controlled protocol or host. The rule's own
instruction is to resolve the `Location` through a real browser parser before
accepting it as same-origin
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Information gain:** separates "the string looked external" (a scanner guess)
from "the authority is external" (a finding). Also decides whether the app's own
defence is parser-based or string-based
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

---

## Step 4 — Scheme-family sweep (three probes, one hypothesis each)

Run these **in order**, because each one tests a different failing link:

| # | Probe | Tests | Pass/fail meaning |
|---|---|---|---|
| 4a | `//yourhost.example/p` | host termination without a scheme | survives ⇒ no scheme check was applied |
| 4b | `https:/\yourhost.example` | scheme parsing under backslash normalisation | survives ⇒ the prefix test was applied to the raw string only |
| 4c | `javascript:` / `data:` | the scheme allowlist itself | survives ⇒ the check inspected a host that does not exist |

The defence corpus: an implementation that does a substring, suffix or
`endsWith` test on the raw string is bypassed by any value whose name merely
contains the allowed host, or which carries an allowed host behind a
credential-holding prefix, because those satisfy the substring test while
resolving elsewhere [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

**Information gain:** identifies *which* invariant is broken, which is what
determines the remediation and whether a partial fix will hold. A report that
says "missing validation" when the truth is "raw-string host comparison" sends
the fix team to the wrong control.

---

## Step 5 — Establish validation mechanism, do not assume it

**Action:** determine whether the destination is (a) unvalidated, (b) allowlisted
with a parser, or (c) checked against a list of known-bad hosts.

**Why (c) matters:** a blocklist is a *real* finding with a different mechanism —
blocklist bypass, not missing validation — and it must not be reported as "no
validation". Any unlisted host is accepted; the corpus's mechanism family for
this class is bypass
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host]
[open_redirect.validation.destination_allowlist_must_be_probed].

**The disproof discipline for mechanism claims** [open_redirect.test.an_open_redirect_defence_that_inspects_the_desti]:
the same disqualifier applies — the test does not apply where the surrounding
behaviour is unobservable, when the response is identical in every case, or when
the only evidence is server-side and not reflected to the requester. The named
boundary is the confusable-host bypass item
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

**Information gain:** converts an unbounded "is this exploitable" into a bounded
"which of three controls is defective" — the answer a reviewer can act on.

---

## Step 6 — Scope the destination to the path, not the origin

**Action:** for every 302 observed during the hunt, resolve the authority and
classify it.

**Information gain:** kills the dominant false positive. A redirect parameter
whose value must resolve to a path on the application's own origin is not an
open redirect; the finding requires the attacker to control the destination
origin, not merely the path or the query string that follows the application's
own host [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].
Note this test is scoped to *server-side* resolution: it is wrong when a client
resolves the value instead — a protocol-relative value, a backslash-normalised
form, or one a downstream client reinterprets as absolute
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

---

## Step 7 — Locate the hop's position in the session

**Action:** determine whether the redirect fires before credentials are entered or
after.

**Information gain:** sets severity and decides whether the pre-auth exception
applies. The consequential open-redirect evidence is the post-authentication hop,
because the pre-auth redirect carries no session while the post-auth one lands
the user on the attacker's page already carrying a fresh session
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].
The pre-auth redirect is independently exploitable when it feeds a
`Referer`-based reset or a poisonable state parameter, or when the page performs
an authenticated action before redirecting
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

---

## Step 8 — If the endpoint is OAuth, run the registration tests instead of the
generic ones

**Action:** vary `client_id` and `redirect_uri` combinations; look for
`redirect_uri_mismatch` versus a 302.

**Information gain:** an authorization server answering with a
`redirect_uri_mismatch` error has refused the unregistered destination, so that
exchange is the authorisation server's defence working and must not be reported
as an open redirect on the client
[open_redirect.test.an_authorization_server_answering_with_a_redirec]
[open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].

The negative test for this step
[open_redirect.test.a_redirect_parameter_whose_value_must_resolve_to]: the
sibling test for a same-site relative-path parameter carries the same
disqualifier — no application where the surrounding behaviour is unobservable
[open_redirect.test.a_redirect_parameter_whose_value_must_resolve_to]
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

**Information gain:** decides whether the chain in Step 9 forms at all.

---

## Step 9 — Chain test: does the open redirect reach the authorize endpoint?

**Action:** if Step 8 produced a 302 to an origin you control from
`redirect_uri`, check whether that response carries an authorization `code` or
`state` you can read.

**Information gain:** the difference between a phishing-grade finding and
account compromise. An open redirect on the OAuth authorize endpoint chains into
authorization-code theft when `redirect_uri` is accepted from user input instead
of an allowlist [open_redirect.chain_link.oauth_authorize_code_interception].

---

## Stop conditions

Stop and report nothing when:

- the controlled host never appears in any `Location` across absolute, relative
  and near-miss variants — the redirect is not user-controllable and validation
  fails [open_redirect.validation.destination_allowlist_must_be_probed];
- every observed `Location` resolves to the request origin
  [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open];
- the only evidence you have is a parameter's presence on a 200
  [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter];
- the response is identical in every case, so there is nothing to observe
  [open_redirect.test.an_open_redirect_is_proved_by_a_3xx_response_who].
