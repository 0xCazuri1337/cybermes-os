# API-to-API Trust Failures

> surface: `api` · CWE: 918 · OWASP: API8:2023
> maturity: **researching** — 15 items, 6 supported, 0 FP rules, 1 chains

A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced.

**Aliases:** api to api trust, internal service trust, shadow api, undocumented api

## Prerequisite

- **A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the endpoint existing.**  
  `under_review` · score 0.9025 · disproved by: The prerequisite is absent if the M2M token is rejected at the token endpoint for the target audience, if the API returns 401 or 403 for the service token where it returns 200 for a user token, or if the endpoint was always intended to be machine-accessible and carries no user-scoped data. In each case there is no trust boundary crossed.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>

## Signal

- **An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never approved.**  
  `under_review` · score 0.899 · disproved by: The signal is false if the unapproved client's token request is denied, or if the granted scopes are empty or narrower than the API actually requires, in which case the permissive policy granted nothing exploitable. It is also false where the client is a first-party app in a tenant where the API is documented as open to any authenticated application.
  sources: <https://tailscale.com/docs/reference/trust-credentials> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>

## Technique

- **An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.**  
  `high_confidence` · score 0.9025 · disproved by: The finding is disproved if API B rejects the foreign-audience token with 401 or 403, if B's expected audience is deliberately the same shared value as A's, or if the 200 was served from a cache rather than an authorization decision. Also disprove it when the token carries a scope B independently enforces, which narrows the impact but does not make the audience check present.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>
- **First, test the \whoami endpoint, which requires authorization: Select + in the Postman workbench to open a new request tab.**  
  `under_review` · score 0.858 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“First, test the \whoami endpoint, which requires authorization: Select + in the ”) does not occur under a test that isolates that control.
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/>
- **Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps.**  
  `high_confidence` · score 0.8465 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Overview Background services and third-party APIs that access your APIs require ”) does not occur under a test that isolates that control.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation> · <https://tailscale.com/docs/reference/trust-credentials>
- **Now test the hello endpoint that doesn't require authorization: Select + in the Postman workbench to open a new request tab.**  
  `under_review` · score 0.8305 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Now test the hello endpoint that doesn't require authorization: Select + in the ”) does not occur under a test that isolates that control.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>
- **When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs.**  
  `high_confidence` · score 0.748 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When enabled, API AM allows you to create an authorization server that establish”) does not occur under a test that isolates that control.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>

## Test

- **A backend trusts an unreachable caller when the server itself will issue a request to an attacker-chosen address that a public client cannot reach, proven by the server's own outbound fetch succeeding where a direct client request to the same address times out.**  
  `high_confidence` · score 0.964 · disproved by: The claim is false if the server's fetch fails the same way yours did - timeout, connection refused, DNS failure - because the difference in network position is the whole point and it has not been shown. It is also false if the marker value you saw was your own input reflected back rather than content the target produced, which is the standard false positive here; the marker must originate on the target side, so use a listener you control or a value only the target could know. And a finding limited to a scheme the server normalizes away, or blocked by an egress allowlist that returns a policy error rather than a fetch, does not demonstrate that the boundary was crossed - report the egress policy as the mitigation it is.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/>
- **A sibling API that does not validate audience is proved by replaying a token minted for API A against API B and reading a B response body that only B holds, which cannot happen unless B accepted a token whose aud names a different service.**  
  `high_confidence` · score 0.934 · disproved by: The claim is false if B rejects every foreign-audience token, and it is also false if the T1 you replayed in fact carries both A and B in its aud, because a token legitimately requested for both services is correctly scoped rather than confused - always decode before replaying. It is further false when B is reached only through a gateway that performs the audience check, so that the API's own 200 is upstream of the decision that actually matters; in that case re-test at the gateway and, if the gateway rejects, report the API as relying on infrastructure rather than as broken. And a 200 whose body is empty or a generic liveness payload is inconclusive, since a service that returns nothing may simply never read the token - repeat against a B endpoint that returns object data.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc8707.html> · <https://www.rfc-editor.org/rfc/rfc9068.html>
- **A machine credential has crossed a user-scoped boundary only when a token carrying a client-credentials grant with no user principal is accepted by a user endpoint and returns data scoped to a specific human principal - a name, an email, an order list, an owner id - rather than a generic service view.**  
  `under_review` · score 0.934 · disproved by: The claim is false if the service token's response is genuinely service-scoped - an integration health summary, an empty list filtered to no principals, a fixed internal identifier, or a 403 naming the missing user context - since none of those is a user's data exposed without a user. It is also false when the credential actually carries a user delegation the tester did not read: a JWT access token with a real sub obtained via the authorization_code or token-exchange flows is a user credential wearing a service label, and the audit requirement is to decode the claims before drawing the boundary conclusion, not to infer from the grant type name. Finally, if the endpoint is genuinely reachable without authentication from the public internet and returns that user's data to anyone, the finding is missing authentication rather than a broken internal trust boundary, and belongs to a different class.
  sources: <https://tailscale.com/docs/reference/trust-credentials> · <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/> · <https://www.rfc-editor.org/rfc/rfc8693.html>
- **Trusting a client-supplied forwarding header is proved when X-Forwarded-For or X-Forwarded-Host changes the server's authorization or routing decision - a 403 becomes a 200, an IP allowlist admits a value the tester supplied, or a generated URL host changes - and not when the header is merely echoed or reflected into a response body.**  
  `high_confidence` · score 0.918 · disproved by: The claim is false if omitting the header produces the same decision, because then the header is inert on that path. It is also false when the value appears only as escaped text in a response body with no effect on any server-side decision, which is reflection rather than trust. Crucially, it is false where a real proxy overwrites the header before the app sees it - the correct pattern is that the proxy appends to the chain and the application reads only the trusted entry, so a test that races a second hop is measuring the wrong layer; establish whether a trusted proxy exists and rewrites the header before reporting. And an endpoint that is public regardless of source IP gives no allowlist decision to subvert, so the pass condition must be an authorization outcome that differs between the two requests.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For>

## Fp Rule

- **Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." and "An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.918 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An access token minted for one audience that is accepted by a sibling " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>
- **Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the..." and "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.8905 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An API whose per-application access policy is permissive rather than g" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>

## Evidence

- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never...**  
  `under_review` · score 0.8355 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (api_trust.fp_rule.auto.derived) states the full boundary.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>

## Impact

- **A service credential keeps minting access tokens after the human or role that created it loses access, so removing a person's privileges does not remove the API access those privileges were used to grant.**  
  `under_review` · score 0.8635 · disproved by: The impact does not hold if token issuance fails after the creator's access is revoked, if the credential is automatically deleted with the account, or if the scopes it carries were already narrower than the revoking role's permissions so no privilege was actually retained. Record the revoked role and the granted scopes to decide which.
  sources: <https://tailscale.com/docs/features/oauth-clients> · <https://tailscale.com/docs/reference/trust-credentials> · <https://www.okta.com/blog/identity-security/beyond-sso-mfa-continuous-identity/>

## Related classes (via chains)

- `ssrf` Server-Side Request Forgery (3 chains)

## Known gaps

Not yet satisfied: `fp_rules`
