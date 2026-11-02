# Methodology — API-to-API Trust Failures

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class api_trust --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced.

**References.** CWE-918 · API8:2023

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the endpoint existing.**

Enumerate the token endpoints the tenant exposes, obtain a client-credentials token for the service principal, and record the audience and scope in the response. Then call the user-facing endpoint with only that token. Okta is explicit that a machine-to-machine sign-in flow is silent and requires no user interaction while still needing the same levels of authentication and authorization, which is the asymmetry to test: the caller is a program with no user behind it and the question is whether the API can tell the difference. Record the status code and whether a response the reference implementation reserves for authenticated users comes back.

- *Disproof:* The prerequisite is absent if the M2M token is rejected at the token endpoint for the target audience, if the API returns 401 or 403 for the service token where it returns 200 for a user token, or if the endpoint was always intended to be machine-accessible and carries no user-scoped data. In each case there is no trust boundary crossed.
- *Evidence:* high_confidence — [developer.okta.com](https://developer.okta.com/docs/guides/protect-your-api/main/); [tailscale.com](https://tailscale.com/docs/features/workload-identity-federation)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never approved.**

For each API in the tenant, read its application access policy for user access and for client access separately. Where the policy is permissive for user access, drive an authorization request from a client you control that has no grant for that API and observe a successful token response rather than an immediate denial. Auth0's evaluation order is the reference: a grant-required policy checks for a matching grant and denies when none exists, while the permissive user-access policy skips the grant check and returns the requested scopes. Record the client_id, the audience and the granted scopes from the response, because that triple is the finding.

- *Disproof:* The signal is false if the unapproved client's token request is denied, or if the granted scopes are empty or narrower than the API actually requires, in which case the permissive policy granted nothing exploitable. It is also false where the client is a first-party app in a tenant where the API is documented as open to any authenticated application.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/blog/developers-guide-api-access-policies-auth0/); [tailscale.com](https://tailscale.com/docs/reference/trust-credentials)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.**

Obtain two tokens from the same tenant, one per audience, and confirm each works against its own API. Then replay token A against API B with nothing changed. A 200 means API B never compared the audience against its own identifier, so any token the tenant ever issues to any client is a valid credential there. Tailscale's federation description of validating standard claims including audience is the reference behaviour, and its note that RS256 permits a token valid for multiple audiences is why one token can otherwise be legitimate everywhere. Record the exact audience of the token and the identifier the second API expects.

- *Disproof:* The finding is disproved if API B rejects the foreign-audience token with 401 or 403, if B's expected audience is deliberately the same shared value as A's, or if the 200 was served from a cache rather than an authorization decision. Also disprove it when the token carries a scope B independently enforces, which narrows the impact but does not make the audience check present.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/secure/tokens/token-best-practices); [tailscale.com](https://tailscale.com/docs/features/workload-identity-federation)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Impact

_What is actually demonstrable, and what to stop claiming._

**A service credential keeps minting access tokens after the human or role that created it loses access, so removing a person's privileges does not remove the API access those privileges were used to grant.**

Have a user with a specific role create a scoped service credential through the documented API or console flow, confirm it works, then revoke that user's access or demote them entirely and wait out any token cache. Request a fresh access token with the stored credential alone. A successful token issuance proves the credential is not bound to the creator's current privileges. Okta documents exactly this, noting that an OAuth client created by a user continues to function and generate access tokens even if the user no longer has access to the tailnet, which is the behaviour to record together with the scope set the credential carries.

- *Disproof:* The impact does not hold if token issuance fails after the creator's access is revoked, if the credential is automatically deleted with the account, or if the scopes it carries were already narrower than the revoking role's permissions so no privilege was actually retained. Record the revoked role and the granted scopes to decide which.
- *Evidence:* high_confidence — [okta.com](https://www.okta.com/blog/identity-security/beyond-sso-mfa-continuous-identity/); [tailscale.com](https://tailscale.com/docs/reference/trust-credentials)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, False-positive rejection, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
