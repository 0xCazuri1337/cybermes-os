# API-to-API Trust Failures

## Definition

A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced.

- **CWE:** 918
- **OWASP:** API8:2023
- **Surface:** api
- **Aliases:** ["api to api trust", "internal service trust", "shadow api", "undocumented api"]

Canonical home for `api_trust`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the endpoint existing.**

Enumerate the token endpoints the tenant exposes, obtain a client-credentials token for the service principal, and record the audience and scope in the response. Then call the user-facing endpoint with only that token. Okta is explicit that a machine-to-machine sign-in flow is silent and requires no user interaction while still needing the same levels of authentication and authorization, which is the asymmetry to test: the caller is a program with no user behind it and the question is whether the API can tell the difference. Record the status code and whether a response the reference implementation reserves for authenticated users comes back.

*Disproof:* The prerequisite is absent if the M2M token is rejected at the token endpoint for the target audience, if the API returns 401 or 403 for the service token where it returns 200 for a user token, or if the endpoint was always intended to be machine-accessible and carries no user-scoped data. In each case there is no trust boundary crossed.

## Attack Surface

Surface: **api**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never approved.**

For each API in the tenant, read its application access policy for user access and for client access separately. Where the policy is permissive for user access, drive an authorization request from a client you control that has no grant for that API and observe a successful token response rather than an immediate denial. Auth0's evaluation order is the reference: a grant-required policy checks for a matching grant and denies when none exists, while the permissive user-access policy skips the grant check and returns the requested scopes. Record the client_id, the audience and the granted scopes from the response, because that triple is the finding.

*Disproof:* The signal is false if the unapproved client's token request is denied, or if the granted scopes are empty or narrower than the API actually requires, in which case the permissive policy granted nothing exploitable. It is also false where the client is a first-party app in a tenant where the API is documented as open to any authenticated application.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never...**

Derived from api_trust.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (api_trust.fp_rule.auto.derived) states the full boundary.

## Exploitation

**Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**

use scope=openid in token-based authentication to avoid having a huge token. You can control any standard OpenID Connect (OIDC) claims that you want to get in the token by adding them as scope values. For example, scope=openid name email family_name address phone_number . To learn more, see Standard Claims on openid.net . 
 You can mix token-based authentication with cookie-based authentication. Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. If you need to, we also return a JWT on the web app flow. Each of our SDKs will do it differently. If you want to call your APIs from JavaScript(instead of using the existing cookie), then you have to set the access tokens using Web Workers or JavaScript closures to handle token transmissions and storage. To learn more, read the Browser in-memory scenarios section of our Token Storage page. 
 ​ R

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".

**If you try to do a redirect with context.redirect , the authentication flow will return an error.**

To execute special logic, you can look at the context.protocol property in your rule. If the value is oauth2-refresh-token , then the rule is running during the exchange. 
 When trying to get a refresh token, the audience parameter is not available on the Rules context object. If you receive an error when attempting to add the audience parameter, verify that you do not have it set on the token. 
 If you try to do a redirect with context.redirect , the authentication flow will return an error. 
 If you have added custom claims to your tokens using a rule, the custom claims will appear in new tokens issued when using a refresh token for as long as your rule is in place. Although new tokens do not automatically inherit custom claims, rules run during the refresh token flow, so the same code will be executed. This allows you to add or change custom claims in newly-issued tokens without fo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".

**Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps.**

Core 3.x API Quickstart Sample Code (opens new window) Note : Several standalone tools can send requests to APIs and allow you to inspect the responses. Our documentation uses Postman and offers Postman Collections (opens new window) to test its APIs more efficiently with a GUI. It also includes HTTP requests as text for those who prefer to use a terminal utility such as cURL (opens new window) . Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps. However, a machine-to-machine sign-in flow is silent and requires no user interaction. Use Okta to grant the correct level of access to your APIs on your behalf. This quickstart contains the following tasks: Check that API Access Management is enabled Create and configure a new web API to use Okta Configure different levels of access for different endpoints Enable CORS for your API Test your API

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Overview Background services and third-party APIs that access your APIs require the same l".

**Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**

use scope=openid in token-based authentication to avoid having a huge token. You can control any standard OpenID Connect (OIDC) claims that you want to get in the token by adding them as scope values. For example, scope=openid name email family_name address phone_number . To learn more, see Standard Claims on openid.net . 
 You can mix token-based authentication with cookie-based authentication. Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. If you need to, we also return a JWT on the web app flow. Each of our SDKs will do it differently. If you want to call your APIs from JavaScript(instead of using the existing cookie), then you have to set the access tokens using Web Workers or JavaScript closures to handle token transmissions and storage. To learn more, read the Browser in-memory scenarios section of our Token Storage page. 
 ​ R

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".

**First, test the \whoami endpoint, which requires authorization: Select + in the Postman workbench to open a new request tab.**

r Password . Select the Headers tab and add two new headers: Name : Cache-Control and Value : no-cache Name : Content-Type and Value : application/x-www-form-urlencoded Click Send to receive an access token. Copy the value returned in the access_token object field and use it for testing your API in the next section. Query the hello and whoami endpoints Now you can test your secured API endpoints. First, test the \whoami endpoint, which requires authorization: Select + in the Postman workbench to open a new request tab. Enter https://localhost:44336/api/whoami for URL . Select the Authorization tab, and then select the Bearer Token for type . Enter the token that you received earlier for Token . Click Send . Ensure that you received a 200 OK response. Select the Authorization tab, and then select No Auth for type . Ensure that you received a 401 Unauthorized response. Now test the hello endpoint that doesn't req

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "First, test the \whoami endpoint, which requires authorization: Select + in the Postman wo".

**If you try to do a redirect with context.redirect , the authentication flow will return an error.**

To execute special logic, you can look at the context.protocol property in your rule. If the value is oauth2-refresh-token , then the rule is running during the exchange. 
 When trying to get a refresh token, the audience parameter is not available on the Rules context object. If you receive an error when attempting to add the audience parameter, verify that you do not have it set on the token. 
 If you try to do a redirect with context.redirect , the authentication flow will return an error. 
 If you have added custom claims to your tokens using a rule, the custom claims will appear in new tokens issued when using a refresh token for as long as your rule is in place. Although new tokens do not automatically inherit custom claims, rules run during the refresh token flow, so the same code will be executed. This allows you to add or change custom claims in newly-issued tokens without fo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".

**When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs.**

eplace it with your Okta domain. Note : For a similar use case where Okta secures a machine-to-machine sign-in flow between a background service app and the Okta APIs, rather than a service app and your own API, see Implement OAuth for Okta with a service app Check that API Access Management is enabled API Access Management (API AM) is the feature in your org that allows Okta to secure your APIs. When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs. All new developer orgs have API AM enabled by default, but it’s optional for production orgs. Check that it’s enabled in your org as follows: Open the Admin Console for your org.
 Sign in to your Okta organization (opens new window) with your administrator account. Click Admin in the upper-right corner of the page. Go to Security > API to view the API AM area. If no Authorization Servers tab exis

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When enabled, API AM allows you to create an authorization server that establishes a secur".

**Now test the hello endpoint that doesn't require authorization: Select + in the Postman workbench to open a new request tab.**

Postman workbench to open a new request tab. Enter https://localhost:44336/api/whoami for URL . Select the Authorization tab, and then select the Bearer Token for type . Enter the token that you received earlier for Token . Click Send . Ensure that you received a 200 OK response. Select the Authorization tab, and then select No Auth for type . Ensure that you received a 401 Unauthorized response. Now test the hello endpoint that doesn't require authorization: Select + in the Postman workbench to open a new request tab. Enter https://localhost:44336/api/hello for URL . Select the Authorization tab, and then select the Bearer Token for type . Enter the token that you received earlier for Token . Click Send . Ensure that you received a 200 OK response. Select the Authorization tab, and then select No Auth for type . Ensure that you still receive a 200 OK response. Next steps Learn more about the concepts introduce

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Now test the hello endpoint that doesn't require authorization: Select + in the Postman wo".

**An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.**

Obtain two tokens from the same tenant, one per audience, and confirm each works against its own API. Then replay token A against API B with nothing changed. A 200 means API B never compared the audience against its own identifier, so any token the tenant ever issues to any client is a valid credential there. Tailscale's federation description of validating standard claims including audience is the reference behaviour, and its note that RS256 permits a token valid for multiple audiences is why one token can otherwise be legitimate everywhere. Record the exact audience of the token and the identifier the second API expects.

*Disproof:* The finding is disproved if API B rejects the foreign-audience token with 401 or 403, if B's expected audience is deliberately the same shared value as A's, or if the 200 was served from a cache rather than an authorization decision. Also disprove it when the token carries a scope B independently enforces, which narrows the impact but does not make the audience check present.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ssrf-to-cloud-metadata-credential-theft` — ssrf-to-cloud-metadata-credential-theft (goal: `cloud_credential_theft`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the..." and "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the...

Adjacent behaviour that produces the same observable result: An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An API whose per-application access policy is permissive rather than g" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." and "An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never...

Adjacent behaviour that produces the same observable result: An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An access token minted for one audience that is accepted by a sibling " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

**A sibling API that does not validate audience is proved by replaying a token minted for API A against API B and reading a B response body that only B holds, which cannot happen unless B accepted a token whose aud names a different service.**

Mint token T1 against API A - request resource=https://a.internal or A's specific audience scope - and decode the payload to confirm aud lists A and not B. Replay the identical Authorization header against B. The pass condition is B returning its own data: a resource identifier that appears nowhere in A's namespace, a B-specific error code, a B-shaped response body. Those last two count, because a B-shaped error proves B parsed the identity out of the token and then failed on its own logic, which is only possible if B got past validation. A B response with an auth-challenge status and an invalid_token error is the required behaviour and fails the test. Run the discriminating third case that separates a real audience gap from a B that simply ignores the token: a token minted for a third, unrelated audience, and a token with a valid A audience but a revoked subject. If B treats all three identically, B is not validating aud at all and the report should say so; if B rejects the unrelated audience but accepts A's, B is validating aud and the finding is not reproduced. Record the decoded aud for every token and the response body keys for every request.

*Disproof:* The claim is false if B rejects every foreign-audience token, and it is also false if the T1 you replayed in fact carries both A and B in its aud, because a token legitimately requested for both services is correctly scoped rather than confused - always decode before replaying. It is further false when B is reached only through a gateway that performs the audience check, so that the API's own 200 is upstream of the decision that actually matters; in that case re-test at the gateway and, if the gateway rejects, report the API as relying on infrastructure rather than as broken. And a 200 whose body is empty or a generic liveness payload is inconclusive, since a service that returns nothing may simply never read the token - repeat against a B endpoint that returns object data.

**Trusting a client-supplied forwarding header is proved when X-Forwarded-For or X-Forwarded-Host changes the server's authorization or routing decision - a 403 becomes a 200, an IP allowlist admits a value the tester supplied, or a generated URL host changes - and not when the header is merely echoed or reflected into a response body.**

Three separate decisions, three separate tests, because they fail independently. Allowlist: find an endpoint that 403s from your address, then send the identical request with X-Forwarded-For set to a loopback or RFC1918 value and re-test - a 200 with real data is the finding, since no proxy sits in front of you to have appended that value. Rate limiting: send a burst that trips a per-IP limit, then repeat the same burst with a different X-Forwarded-For per request and record whether all N requests succeed; if the limit counts the header value, the limiter is attacker-controllable. Host: send X-Forwarded-Host: attacker.example and look for the value in an absolute URL the server generated - a password-reset link, a callback, an absolute redirect - rather than in reflected markup, which most frameworks escape harmlessly. For each, run the negative control by omitting the header on the same request and confirm the decision differs. Record the exact header, the exact endpoint, and the two status codes.

*Disproof:* The claim is false if omitting the header produces the same decision, because then the header is inert on that path. It is also false when the value appears only as escaped text in a response body with no effect on any server-side decision, which is reflection rather than trust. Crucially, it is false where a real proxy overwrites the header before the app sees it - the correct pattern is that the proxy appends to the chain and the application reads only the trusted entry, so a test that races a second hop is measuring the wrong layer; establish whether a trusted proxy exists and rewrites the header before reporting. And an endpoint that is public regardless of source IP gives no allowlist decision to subvert, so the pass condition must be an authorization outcome that differs between the two requests.

**A machine credential has crossed a user-scoped boundary only when a token carrying a client-credentials grant with no user principal is accepted by a user endpoint and returns data scoped to a specific human principal - a name, an email, an order list, an owner id - rather than a generic service view.**

Get a token the way a backend service would: client_credentials grant, no user login, no on-behalf-of, and record the token's claims so you can prove what it is (typically client_id or azp with no sub, or an explicit sub naming the service principal). Then call the endpoint that the documentation and the frontend traffic describe as user-scoped - /me, /api/users/me/orders, /profile, anything whose response shape is a person's data. The pass condition is a 200 whose body contains a specific user's fields rather than an aggregate or an empty collection, because that means the API resolved a real principal without a user in the credential. The two control requests make it falsifiable: the same endpoint with no Authorization header must be rejected, which shows a boundary exists rather than the endpoint being public; and the same endpoint with a human's own token must return that human's data, which shows the field is user-scoped rather than shared. Then re-run the service token against a second user-scoped path and record whether it returns the same fixed principal every time - a service token resolving to one fixed human is a worse and clearer finding than one returning varying data.

*Disproof:* The claim is false if the service token's response is genuinely service-scoped - an integration health summary, an empty list filtered to no principals, a fixed internal identifier, or a 403 naming the missing user context - since none of those is a user's data exposed without a user. It is also false when the credential actually carries a user delegation the tester did not read: a JWT access token with a real sub obtained via the authorization_code or token-exchange flows is a user credential wearing a service label, and the audit requirement is to decode the claims before drawing the boundary conclusion, not to infer from the grant type name. Finally, if the endpoint is genuinely reachable without authentication from the public internet and returns that user's data to anyone, the finding is missing authentication rather than a broken internal trust boundary, and belongs to a different class.

**A backend trusts an unreachable caller when the server itself will issue a request to an attacker-chosen address that a public client cannot reach, proven by the server's own outbound fetch succeeding where a direct client request to the same address times out.**

The test needs a control the attacker cannot forge, so the standard loopback trick - point the callback at 127.0.0.1:port - only works when nothing else is listening and the response proves the server fetched it. Set up a listener that returns a distinctive body containing a unique marker, aim the parameterised field at that listener's address, and record which of two things happened. Direct-from-your-seat attempt first: request the same address yourself and note whether it times out or is refused by the egress policy. If your own request is blocked and the server's request is answered, the difference is the server's network position, and that is the finding - an internal-only endpoint or metadata service the server will reach on your behalf. The second, weaker case is a public address that returns a marker proving the server fetched it: that is SSRF, and it needs the same control, since a marker only proves a fetch if it came back through the response body rather than being reflected from your own input. Record the marker, the URL, the response containing it, and the paired direct-attempt failure.

*Disproof:* The claim is false if the server's fetch fails the same way yours did - timeout, connection refused, DNS failure - because the difference in network position is the whole point and it has not been shown. It is also false if the marker value you saw was your own input reflected back rather than content the target produced, which is the standard false positive here; the marker must originate on the target side, so use a listener you control or a value only the target could know. And a finding limited to a scheme the server normalizes away, or blocked by an egress allowlist that returns a policy error rather than a fetch, does not demonstrate that the boundary was crossed - report the egress policy as the mitigation it is.

## Impact

**A service credential keeps minting access tokens after the human or role that created it loses access, so removing a person's privileges does not remove the API access those privileges were used to grant.**

Have a user with a specific role create a scoped service credential through the documented API or console flow, confirm it works, then revoke that user's access or demote them entirely and wait out any token cache. Request a fresh access token with the stored credential alone. A successful token issuance proves the credential is not bound to the creator's current privileges. Okta documents exactly this, noting that an OAuth client created by a user continues to function and generate access tokens even if the user no longer has access to the tailnet, which is the behaviour to record together with the scope set the credential carries.

*Disproof:* The impact does not hold if token issuance fails after the creator's access is revoked, if the credential is automatically deleted with the account, or if the scopes it carries were already narrower than the revoking role's permissions so no privilege was actually retained. Record the revoked role and the granted scopes to decide which.

## Related Bug Classes

Not yet researched.

## References

- **auth0.com** (writeup)
  - <https://auth0.com/blog/developers-guide-api-access-policies-auth0/>
  - <https://auth0.com/docs/secure/tokens/token-best-practices>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/918.html>
- **developer.mozilla.org** (writeup)
  - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For>
- **developer.okta.com** (docs)
  - <https://developer.okta.com/docs/guides/protect-your-api/main/>
- **okta.com** (blog)
  - <https://www.okta.com/blog/identity-security/beyond-sso-mfa-continuous-identity/>
- **owasp.org** (writeup)
  - <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>
  - <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc8693.html>
  - <https://www.rfc-editor.org/rfc/rfc8707.html>
  - <https://www.rfc-editor.org/rfc/rfc9068.html>
- **tailscale.com** (docs)
  - <https://tailscale.com/docs/features/oauth-clients>
  - <https://tailscale.com/docs/features/workload-identity-federation>
  - <https://tailscale.com/docs/reference/trust-credentials>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
