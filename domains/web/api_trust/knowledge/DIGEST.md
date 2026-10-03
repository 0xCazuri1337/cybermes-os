# API-to-API Trust Failures

> surface: `api` · CWE: 918 · OWASP: API8:2023
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced.

**Aliases:** api to api trust, internal service trust, shadow api, undocumented api

## Prerequisite

- **A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the endpoint existing.**  
  `high_confidence` · score 0.9025 · disproved by: The prerequisite is absent if the M2M token is rejected at the token endpoint for the target audience, if the API returns 401 or 403 for the service token where it returns 200 for a user token, or if the endpoint was always intended to be machine-accessible and carries no user-scoped data. In each case there is no trust boundary crossed.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>

## Signal

- **An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never approved.**  
  `high_confidence` · score 0.875 · disproved by: The signal is false if the unapproved client's token request is denied, or if the granted scopes are empty or narrower than the API actually requires, in which case the permissive policy granted nothing exploitable. It is also false where the client is a first-party app in a tenant where the API is documented as open to any authenticated application.
  sources: <https://tailscale.com/docs/reference/trust-credentials> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>

## Technique

- **An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.**  
  `high_confidence` · score 0.9025 · disproved by: The finding is disproved if API B rejects the foreign-audience token with 401 or 403, if B's expected audience is deliberately the same shared value as A's, or if the 200 was served from a cache rather than an authorization decision. Also disprove it when the token carries a scope B independently enforces, which narrows the impact but does not make the audience check present.
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://tailscale.com/docs/features/workload-identity-federation>
- **First, test the \whoami endpoint, which requires authorization: Select + in the Postman workbench to open a new request tab.**  
  `high_confidence` · score 0.858 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "First, test the \whoami endpoint, which requires authorization: Select + in the Postman wo".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/>
- **Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps.**  
  `high_confidence` · score 0.8465 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Overview Background services and third-party APIs that access your APIs require the same l".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>
- **Now test the hello endpoint that doesn't require authorization: Select + in the Postman workbench to open a new request tab.**  
  `high_confidence` · score 0.8305 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Now test the hello endpoint that doesn't require authorization: Select + in the Postman wo".
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>
- **If you try to do a redirect with context.redirect , the authentication flow will return an error.**  
  `high_confidence` · score 0.803 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/>
- **If you try to do a redirect with context.redirect , the authentication flow will return an error.**  
  `high_confidence` · score 0.803 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/>
- **When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs.**  
  `high_confidence` · score 0.764 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When enabled, API AM allows you to create an authorization server that establishes a secur".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://tailscale.com/docs/features/workload-identity-federation>
- **Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/>
- **Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://developer.okta.com/docs/guides/protect-your-api/main/>

## Fp Rule

- **Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." and "An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.894 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An access token minted for one audience that is accepted by a sibling " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>
- **Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the..." and "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8665 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An API whose per-application access policy is permissive rather than g" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://developer.okta.com/docs/guides/protect-your-api/main/> · <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>

## Impact

- **A service credential keeps minting access tokens after the human or role that created it loses access, so removing a person's privileges does not remove the API access those privileges were used to grant.**  
  `high_confidence` · score 0.8635 · disproved by: The impact does not hold if token issuance fails after the creator's access is revoked, if the credential is automatically deleted with the account, or if the scopes it carries were already narrower than the revoking role's permissions so no privilege was actually retained. Record the revoked role and the granted scopes to decide which.
  sources: <https://tailscale.com/docs/features/oauth-clients> · <https://tailscale.com/docs/reference/trust-credentials> · <https://www.okta.com/blog/identity-security/beyond-sso-mfa-continuous-identity/>

## Related classes (via chains)

- `ssrf` Server-Side Request Forgery (3 chains)
