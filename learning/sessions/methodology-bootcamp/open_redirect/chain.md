# chain — open redirect as the entry point of a compromise chain

The corpus holds exactly one chain item for this class, and it is the one that
sets the class's severity ceiling. An open redirect on its own is a phishing
pivot. An open redirect inside an OAuth flow is the first step of account
compromise.

---

## Chain 1 — Open redirect → OAuth authorization-code theft → account takeover

**Prerequisite.** User-supplied input reaches the destination of a redirect
without validation [open_redirect.signal.user_input_reaches_redirect_destination]
— and specifically, an OAuth/OIDC authorize endpoint accepts `redirect_uri` from
the request rather than resolving it from a server-side client registration.

**Transition.** The attacker sends the victim an authorize link whose
`redirect_uri` points at an origin the attacker controls. The server authenticates
the victim as usual and then emits a 3xx whose `Location` carries the
authorization `code` (and `state`) to that origin. This is exactly the chain the
corpus records: an open redirect on the OAuth authorize endpoint chains into
authorization-code theft when `redirect_uri` is accepted from user input instead
of an allowlist [open_redirect.chain_link.oauth_authorize_code_interception].

**Escalation.** A phishing redirect asks the victim for credentials and usually
fails; an intercepted authorization code is a *bearer* credential that
authenticates as the victim without any password, second factor, or user
interaction at the redemption step. So the same class name carries two entirely
different impacts — credential phishing, where the post-authentication hop lands
the user on the attacker's page already carrying a fresh session
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it],
versus code interception, where no further interaction is required. Triaging
this class on "does it leave the origin" alone collapses those two into one
severity and both reports get under-rated.

**Blocker at this step.** The chain does not form if the authorize endpoint
rejects or ignores an unregistered `redirect_uri` and the `Location` stays on an
allowlisted origin — in that case the finding is a normal post-login navigation,
not a vulnerability
[open_redirect.chain_link.oauth_authorize_code_interception]. Operationally that
blocker is the authorization server answering `redirect_uri_mismatch`
[open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].

**Two escapes from the blocker, both of which must be tested before the chain is
closed:**

1. **The client holds a pre-registered wildcard or prefix pattern the server
   honours**, so an attacker's host matches a registered pattern and the code is
   returned to it. Here the *client* is the component at fault, and the server's
   exact-match rule is not the control that stopped the attack.
2. **The mismatch was only for the tested variant** while a weaker registered
   form still accepts the malicious origin
   [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect].

Either escape means the mismatch error is evidence about *that payload shape*,
not about the flow's safety
[open_redirect.test.an_authorization_server_answering_with_a_redirec].

---

## Chain 2 — Open redirect → referrer/state leakage → account recovery takeover
(the pre-auth branch)

**Prerequisite.** An open redirect on an unauthenticated entry point — normally
the lower-severity shape, since the pre-auth redirect carries no session
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

**Transition.** The redirect fires before credentials are entered, and its
destination or query string carries material the victim's browser will leak or a
downstream consumer will process.

**Escalation.** The corpus names the exact triggers that make a pre-auth redirect
independently exploitable: it feeds a `Referer`-based reset or a state parameter
that the attacker can poison, or the page performs an authenticated action before
redirecting [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

**Blocker at this step.** No post-login session to steal, and the destination
must actually receive the material. The same-origin boundary applies here too:
if the destination resolves to the application's own host, no request ever left
the origin and there is nothing to leak
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Consequence for triage.** "Pre-auth, therefore minor" is the wrong inference.
The post-authentication hop is the *consequential* evidence as a rule
[open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it],
but its own disproof is the pre-auth exception — so the two must be tested, not
assumed, and the disproof must be quoted in the report when it applies.

---

## Chain 3 — Open redirect → chained redirector → phishing

**Prerequisite.** A `Location` that resolves same-origin, which on the raw-string
test looks safe.

**Transition.** The same-origin destination is itself an open redirector the
application chains to — named explicitly in the same-origin rule's disproof
[open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open]. The
authority differs only after the full resolution chain, which is why the rule
insists on resolving the `Location` through a real browser parser before
accepting it as same-origin [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open].

**Escalation.** Same as Chain 1's first hop: phishing credibility off a trusted
origin [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it].

**Blocker at this step.** The terminal redirector must itself be shown to leave
the origin. Without that, this chain is asserted, not proved.

---

## Chain 4 — Open redirect → client-side resolution → off-origin navigation
(the non-browser consumer branch)

**Prerequisite.** A server-side same-origin check that *passes*.

**Transition.** The value is resolved by a client rather than the server —
protocol-relative, scheme-relative, backslash-normalised, or reinterpreted as
absolute by an email client, chat renderer, or mobile deep-link handler. The
server-side check passes while the user agent still leaves the origin
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

**Escalation.** whichever of Chains 1–3 the terminal destination enables.

**Blocker at this step.** Resolution must be shown in the actual consuming client,
not inferred from the server response. A same-origin server response is not a
disproof here — the same-site rule is scoped to server-side resolution
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].

---

## Chain-control summary: what actually breaks this class

| Broken control | What it would stop | Named by |
|---|---|---|
| Parser-based allowlist, exact parsed-host equality, rejecting relative and scheme-relative input | Chains 1, 3, 4 and all three scheme families | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] |
| Server-side `redirect_uri` exact-match registration with no wildcard/prefix patterns | Chain 1 | [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect] [open_redirect.chain_link.oauth_authorize_code_interception] |
| A blocklist of known-bad hosts | **Nothing reliably** — an unlisted host is accepted. This is a real finding with a different mechanism, blocklist bypass, not missing validation, and it must not be reported as "no validation". | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] [open_redirect.validation.destination_allowlist_must_be_probed] |
| A server-side relative-path-only check | Nothing, once a client resolves the value | [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect] |
