# Methodology — API-to-API Trust Failures

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class api_trust --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced.

**References.** CWE-918 · API8:2023

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An access token minted for one audience that is accepted by a sibling API proves the resource server is not validating the audience claim, and the test is a straight cross-audience replay of one legitimate token against a second endpoint.**

Obtain two tokens from the same tenant, one per audience, and confirm each works against its own API. Then replay token A against API B with nothing changed. A 200 means API B never compared the audience against its own identifier, so any token the tenant ever issues to any client is a valid credential there. Tailscale's federation description of validating standard claims including audience is the reference behaviour, and its note that RS256 permits a token valid for multiple audiences is why one token can otherwise be legitimate everywhere. Record the exact audience of the token and the identifier the second API expects.

- *Disproof:* The finding is disproved if API B rejects the foreign-audience token with 401 or 403, if B's expected audience is deliberately the same shared value as A's, or if the 200 was served from a cache rather than an authorization decision. Also disprove it when the token carries a scope B independently enforces, which narrows the impact but does not make the audience check present.
- *Evidence:* high_confidence — [developer.okta.com](https://developer.okta.com/docs/guides/protect-your-api/main/); [tailscale.com](https://tailscale.com/docs/features/workload-identity-federation)

**Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps.**

Core 3.x API Quickstart Sample Code (opens new window) Note : Several standalone tools can send requests to APIs and allow you to inspect the responses. Our documentation uses Postman and offers Postman Collections (opens new window) to test its APIs more efficiently with a GUI. It also includes HTTP requests as text for those who prefer to use a terminal utility such as cURL (opens new window) . Overview Background services and third-party APIs that access your APIs require the same levels of authentication and authorization (opens new window) as users who access your web apps. However, a machine-to-machine sign-in flow is silent and requires no user interaction. Use Okta to grant the correct level of access to your APIs on your behalf. This quickstart contains the following tasks: Check that API Access Management is enabled Create and configure a new web API to use Okta Configure different levels of access for different endpoints Enable CORS for your API Test your API

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Overview Background services and third-party APIs that access your APIs require ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [developer.okta.com](https://developer.okta.com/docs/guides/protect-your-api/main/); [tailscale.com](https://tailscale.com/docs/features/workload-identity-federation)

**When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs.**

eplace it with your Okta domain. Note : For a similar use case where Okta secures a machine-to-machine sign-in flow between a background service app and the Okta APIs, rather than a service app and your own API, see Implement OAuth for Okta with a service app Check that API Access Management is enabled API Access Management (API AM) is the feature in your org that allows Okta to secure your APIs. When enabled, API AM allows you to create an authorization server that establishes a security boundary for your APIs. All new developer orgs have API AM enabled by default, but it’s optional for production orgs. Check that it’s enabled in your org as follows: Open the Admin Console for your org.
 Sign in to your Okta organization (opens new window) with your administrator account. Click Admin in the upper-right corner of the page. Go to Security > API to view the API AM area. If no Authorization Servers tab exis

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When enabled, API AM allows you to create an authorization server that establish”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [developer.okta.com](https://developer.okta.com/docs/guides/protect-your-api/main/); [tailscale.com](https://tailscale.com/docs/features/workload-identity-federation)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, False-positive rejection, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
