# hypothesize — falsifiable hypotheses keyed to observed signals

Every hypothesis below names the observation that produced it and the observation
that would refute it. A claim is not a hypothesis; an unrefutable claim is a
finding you will get rejected for.

---

## H1 — "There is no destination validation at all"

**Signal observed:** a `next`/`retUrl` value taken from the login bounce is
echoed verbatim into the `Location` of the resulting 3xx
[open_redirect.technique.hth_if_the_site_prompts_for_a_login].

**Mechanism claim:** the application performs no destination check, so any
attacker-controlled authority is emitted.

**Falsified by:** a controlled external host never appears in the `Location`
across absolute, relative and near-miss variants — that is the corpus's own
invalidation of an open-redirect claim when the redirect turns out not to be
user-controllable [open_redirect.validation.destination_allowlist_must_be_probed].

---

## H2 — "The destination is allowlisted, and the allowlist holds" (the negative
hypothesis, stated first)

**Signal observed:** the same login-bounce parameter exists
[open_redirect.technique.hth_if_the_site_prompts_for_a_login] but the site
returns the parameter to a fixed internal route regardless of value.

**Falsified by:** one request whose `Location` host is outside the origin
[open_redirect.signal.user_input_reaches_redirect_destination]. **This hypothesis
must be tested first.** A hunter who assumes H1 and writes it up without testing
H2 produces exactly the padding that the corpus's false-positive log rejects: a
302 that pointed back at the same host with the parameter echoed proves nothing,
because no request ever left the origin.

---

## H3 — "Validation is present but is a raw-string test, so the authority check
can be defeated without any parser"

**Signal observed:** the app clearly *does* inspect the destination — a
confusable or userinfo-laden host survives the first probe.

**Mechanism claim:** an implementation that does a substring, suffix or
`endsWith` test on the raw string is bypassed by any value whose name merely
contains the allowed host, or which carries an allowed host behind a
credential-holding prefix, because those satisfy the substring test while
resolving elsewhere [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

**Falsified by:** the app parsing with a WHATWG-compatible URL constructor and
comparing the parsed host for exact equality — then the confusable forms fail to
match and no substring confusion is possible; a check that also rejects relative
and scheme-relative input closes the remaining variants
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

**This hypothesis is the one that must not be reported as "no validation".** It
is a *real* finding with a different mechanism. Mechanism identity is the whole
difference between a remediation ("add an allowlist") and a correct one ("stop
comparing raw strings").

---

## H4 — "Protocol-relative input breaks host termination"

**Signal observed:** the app rejects anything not starting with its own scheme, and
a value beginning `//` nonetheless leaves the origin.

**Mechanism claim:** the value carries no scheme, so the scheme check never
evaluates and the authority begins at `//`. Server-side it still looks like a
same-origin relative path
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Falsified by:** the app rejecting scheme-relative and relative input outright —
that single additional rule closes this variant, per the corpus's own note that a
check which rejects relative and scheme-relative input closes the remaining
variants [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

---

## H5 — "Backslash normalisation breaks scheme parsing"

**Signal observed:** the app accepts only values beginning `https://app.example`,
and yet `https:/\evil.example` (or `https:\\evil.example`) leaves the origin.

**Mechanism claim:** the string passes the scheme prefix test, then the user
agent's parser folds the backslash into a path separator and reads the authority
as the attacker host. The same convergence of raw string and parsed authority is
what makes the same-origin rule unsound without a real browser parser
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Falsified by:** the app rejecting backslashes and control characters in the
parameter, or normalising then re-validating after decoding — after which the
folded form no longer starts with the expected prefix
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

---

## H6 — "The destination is resolved by a client, not the server"

**Signal observed:** the server-side check passes for a value you believe is
external; the value is protocol-relative, backslash-normalised, or something a
downstream consumer (mail client, chat renderer, mobile deep-link handler)
reinterprets as absolute.

**Mechanism claim:** the same-site rule is stated for server-side resolution; it
is wrong when a client resolves the value instead, because the server-side check
passes while the user agent still leaves the origin
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

**Falsified by:** a single deterministic `Location` whose parsed authority equals
the request host in a real browser, with no downstream re-resolution step
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].
**Testable discriminator:** the same request served to a real browser versus a
raw HTTP client — divergent authority means client-side resolution.

---

## H7 — "The redirect feeds an OAuth authorize endpoint"

**Signal observed:** a `redirect_uri` parameter on an authorize request that is
accepted from request input rather than resolved from a server-side client
registration.

**Mechanism claim:** an open redirect on the authorize endpoint chains into
authorization-code theft when `redirect_uri` is accepted from user input instead
of an allowlist [open_redirect.chain_link.oauth_authorize_code_interception].

**Falsified by:** the authorize endpoint rejecting or ignoring an unregistered
`redirect_uri` and the `Location` staying on an allowlisted origin — then the
chain does not form and the finding is a normal post-login navigation
[open_redirect.chain_link.oauth_authorize_code_interception]. Concretely, an
authorization server answering with a `redirect_uri_mismatch` error has refused
the unregistered destination [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].
**Also falsified by:** the observed redirect being on a bare unauthenticated entry
point carrying no session, where the post-authentication argument for severity
does not apply
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

---

## Ordering rule for these hypotheses

H2 is the negative control and H1 its opposite; H3–H6 are only reachable *after*
H1 is falsified by a positive. Committing to "the app validates but validates
badly" (H3) before you have evidence that any validation exists is how a hunter
ends up reporting a blocklist bypass as a missing-validation bug — the corpus
names this as a distinct mechanism, not a distinct absence
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].
