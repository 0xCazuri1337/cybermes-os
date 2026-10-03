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

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.**

Obtain two tokens from the same tenant, one per audience, and confirm each works against its own API. Then replay token A against API B with nothing changed. A 200 means API B never compared the audience against its own identifier, so any token the tenant ever issues to any client is a valid credential there. Tailscale's federation description of validating standard claims including audience is the reference behaviour, and its note that RS256 permits a token valid for multiple audiences is why one token can otherwise be legitimate everywhere. Record the exact audience of the token and the identifier the second API expects.

- *Disproof:* The finding is disproved if API B rejects the foreign-audience token with 401 or 403, if B's expected audience is deliberately the same shared value as A's, or if the 200 was served from a cache rather than an authorization decision. Also disprove it when the token carries a scope B independently enforces, which narrows the impact but does not make the audience check present.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/secure/tokens/token-best-practices); [tailscale.com](https://tailscale.com/docs/features/workload-identity-federation)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." and "An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never...

Adjacent behaviour that produces the same observable result: An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An access token minted for one audience that is accepted by a sibling " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/blog/developers-guide-api-access-policies-auth0/); [developer.okta.com](https://developer.okta.com/docs/guides/protect-your-api/main/)

**Reject a api_trust finding until it is distinguished from the adjacent behaviour this class also covers. "A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the..." and "An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A machine-to-machine client credential that reaches an API path intended only for logged-in users is the prerequisite for api_trust findings, and it must be shown by obtaining the M2M token and replaying it rather than inferred from the...

Adjacent behaviour that produces the same observable result: An API whose per-application access policy is permissive rather than grant-based will mint a token for any registered client, so the observable signal is not a failed request but a successful token issuance from a client the target never...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An API whose per-application access policy is permissive rather than g" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/blog/developers-guide-api-access-policies-auth0/); [developer.okta.com](https://developer.okta.com/docs/guides/protect-your-api/main/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
