# generalize — variant map

## Common variants

| Variant | Shape | Why it works | Anchor |
|---|---|---|---|
| **Login-bounce `next`** | `GET /login?next=https://evil/` → 302 after auth | The redirect parameter carried in a login URL is the post-login destination the user influences. | [open_redirect.technique.hth_if_the_site_prompts_for_a_login] |
| **Generic `returnUrl`/`redirect`/`continue`** | Any GET endpoint that 302s | User input reaches the destination of a redirect without validation. | [open_redirect.signal.user_input_reaches_redirect_destination] |
| **OAuth authorize `redirect_uri`** | 302 carrying the code to a non-allowlisted origin | Accepted from user input instead of an allowlist. | [open_redirect.chain_link.oauth_authorize_code_interception] |
| **Protocol-relative** | `//evil.example/p` | Breaks **host termination**; no scheme present, so a scheme check never runs. | [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] |
| **Backslash-normalised** | `https:/\evil.example` | Breaks **scheme parsing**; passes the raw prefix test, then the parser folds the backslash. | [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] |
| **Userinfo confusion** | `https://app.example@evil.example/` | Satisfies a raw substring test; parsed authority is the attacker host. | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] |
| **Non-standard 3xx** | 303/307/308 rather than 302 | Redirection to a different resource identified by `Location`; the family is broad by design. | [open_redirect.evidence.early_user_agents_split_on_whether_the_metho] [open_redirect.evidence.note_in_http_1_0_the_status_codes_301_moved] |

## Uncommon variants

| Variant | Shape | Why it works | Anchor |
|---|---|---|---|
| **`Content-Location` on a 2xx** | 200 with an absolute `Content-Location` naming another resource | Same class of trust decision, reached by a different field — and it defeats a `Location`-only scanner. | [open_redirect.evidence.if_the_response_has_a_content_location_heade] |
| **Meta-refresh / client-side navigation** | No 3xx at all; a rendered navigational directive | Different mechanism, same impact. *(Inference, scoped: the corpus's proof item is stated for a 3xx `Location` — [open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter] — so this variant must be argued from the destination-origin invariant instead, [open_redirect.signal.user_input_reaches_redirect_destination].)* | invariant anchor as above |
| **Dangerous scheme** | `javascript:` / `data:` in the destination | Breaks the **scheme allowlist** entirely: there is no host to validate. | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] |
| **Front-end-router resolution** | Server-side check passes; the SPA router or a downstream consumer resolves against an attacker-controlled protocol/host | The server-side check passes while the user agent still leaves the origin. | [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect] |
| **Non-browser consumers** | The same URL opened by an email client, chat renderer, or mobile deep-link handler | The same-site rule is stated for server-side resolution; a downstream client can re-resolve the value as absolute. | [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect] |
| **Redirect chaining** | A same-origin `Location` that itself 302s off-origin | Named explicitly in the same-origin rule's disproof: an open redirector the app itself chains to. | [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] |
| **IDN / punycode homograph** | Host that renders as the app's brand | Named in the same-origin rule's disproof; only a real parser plus exact host comparison defeats it. | [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] |
| **Pre-auth-only redirect** | The 302 fires before credentials | Normally lower severity — no session is carried — but independently exploitable when it feeds a `Referer`-based reset or a poisonable state parameter, or when the page acts before redirecting. | [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it] |
| **Weak registered OAuth pattern** | Client pre-registers a wildcard/prefix the server honours | The mismatch-error rule is wrong when an attacker's host matches a registered pattern. | [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect] |

## Defensive variants — and their own failure mode

Each defensive shape is a distinct mechanism, and each has a named way of
failing. A report that says "missing validation" when the app actually runs one of
these is wrong about the defect.

| Defence | What it does | How it fails | Anchor |
|---|---|---|---|
| **Parser-based allowlist with exact host equality** | WHATWG URL constructor, exact parsed-host comparison | Does not fail by confusion; confusable forms simply fail to match. Rejects relative and scheme-relative input too, which closes the remaining variants. | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] |
| **Raw substring / suffix / `endsWith` check** | Compares the raw string | Defeated by a host that merely contains the allowed host, or by an allowed host behind a credential-holding prefix. | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] |
| **Blocklist of known-bad hosts** | Rejects listed hosts only | **A real finding with a different mechanism — blocklist bypass, not missing validation.** Any unlisted host is accepted; must be reported as such and must not be written up as "no validation". | [open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host] [open_redirect.validation.destination_allowlist_must_be_probed] |
| **Scheme allowlist only** | Checks the value starts with `https://app.example` | Blind to protocol-relative input, which never uses a scheme; and to backslash-normalised input that passes the prefix then normalises away. | [open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open] |
| **Server-side relative-path check only** | Requires the value to resolve to a path on the app's own origin | Wrong when a client resolves the value instead — protocol-relative, backslash-normalised, or reinterpreted as absolute downstream. | [open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect] |
| **Exact-match OAuth `redirect_uri` registration** | Server refuses unregistered destinations, answering `redirect_uri_mismatch` | Correct defence — must not be reported as an open redirect. Wrong only when a pre-registered wildcard/prefix pattern is honoured, or a weaker registered form still accepts the malicious origin. | [open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect] |
| **Tenant-configured third-party `redirect_uri`** | External origin is the app's own registered callback | Not an open redirect in the tenant's web app — unless reachable with an unregistered `client_id` or a client whose `redirect_uri` is fixed to the app's own origin. | [open_redirect.fp_rule.registered_oauth_redirect_uri_is_not_a_webapp_open_redirect] |
| **Session-gated redirect** | Destination only meaningful post-login | Not a defence — it raises severity. The post-authentication hop lands the user on the attacker's page already carrying a fresh session, which is why that hop is the consequential evidence. | [open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it] |

## Mapping the variants back onto the invariant

Every row above is one of three failures, and naming which is what makes the
finding actionable: **host termination** (protocol-relative, userinfo,
front-end-router resolution), **scheme parsing under normalisation**
(backslash, tab/CR), or **the scheme allowlist itself** (dangerous schemes,
blocklist-as-scheme-check). The closing condition the corpus names for the
defensive side — parse with a WHATWG-compatible constructor, compare the parsed
host for exact equality, and reject relative and scheme-relative input — is what
closes all three at once
[open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host].

The boundary every variant is tested against: the attacker must control the
**destination origin**, not merely the path or the query string after the
application's own host
[open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect].
