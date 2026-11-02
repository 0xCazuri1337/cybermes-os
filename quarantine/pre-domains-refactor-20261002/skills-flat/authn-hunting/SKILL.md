---
name: authn-hunting
description: Use when hunting Authentication Failures in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Authentication Failures — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE 287 · OWASP A07:2021
> evidence: 8 items, 8 supported, 3 FP rules, 1 chains
> maturity: **researching** — missing: items

The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

**Also called:** authentication bypass, weak login, password reset flaw, mfa bypass, account takeover


## Prerequisites (do not start without these)

- SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.
  - **Disproof:** If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>

## Validation bar (how to prove it)

- A session-puzzling candidate is confirmed only when a pre-authentication session variable, set before credentials are supplied, still determines the authenticated identity or an authorization decision after login.
  - **Disproof:** Refuted when the post-login session resolves to the principal whose credentials were just presented, the mutated variable is overwritten rather than merged at the authentication transition, and the authorization-gated action denied in the baseline remains denied; a session value that cannot survive authentication cannot produce an authority differential.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>

## False-positive rules (when to reject it)

- An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.
  - **Disproof:** Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://portswigger.net/web-security/oauth>
- A session variable populated before login that carries no privilege and is discarded at authentication is session-puzzling surface, not an authentication bypass, and is only a bypass once the pre-login value determines an authenticated identity.
  - **Disproof:** Refuted when the session variable observed before authentication is never read on any post-login code path, or when the post-login session resolves exclusively from the credential just presented and the edited pre-login value is overwritten rather than merged; a token that carries no principal and confers no authority cannot be an authentication bypass.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Variants

- A SAML relying party that validates a signature without pinning which element the signature must cover is vulnerable to XML signature wrapping, where a forged unsigned assertion is supplied alongside a legitimately signed one.
  - **Disproof:** If the relying party rejects any document whose signature does not cover the assertion it consumes, and a wrapped variant yields no session, wrapping is not present.
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Defence bypasses

- An OAuth device authorization grant completed by a user is a legitimate authorization flow unless the resulting token is accepted by an endpoint that was never meant to honour that provisioner, which is the actual bypass condition.
  - **Disproof:** Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242> · <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>

## Chaining opportunities

- A SAML relying party that validates a signed assertion without pinning which assertion in the response it trusts accepts an attacker-injected second assertion, so the session it establishes is bound to an identity the identity provider never asserted.
  - **Disproof:** Refuted when the relying party rejects any SAML response containing more than one assertion, or when it verifies the signature over the exact assertion element it then consumes rather than over the enclosing response; either control makes the injected assertion unreachable regardless of how many elements the response carries.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://cwe.mitre.org/data/definitions/347.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- An OAuth login flow that omits the state parameter does not yield account takeover on its own but binds the victim to the attacker's identity through login CSRF, and it is the account binding rather than the token theft that carries the chain.
  - **Disproof:** Refuted when the client compares the returned state against the value it stored at initiation and rejects a mismatch, or when the site offers a non-OAuth login path the attacker cannot reach; without an unbound callback or a lax redirect_uri there is no login CSRF primitive to chain.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/oauth>

## Rejected before you report

- **A session variable set before login and carried into the authenticated session makes the pre-login identity authoritative, so editing it yields an authentication bypass.**
  - Killed by: The mutated variable is overwritten at the authentication transition rather than merged, so both sessions resolve to the credential just presented and the gated action stays denied; the variable was a locale or theme value with no authority.
  - Rule: A pre-auth session variable is an authentication bypass only when it survives the login transition with authority: prove the post-login session resolves to a principal you did not authenticate as, or that an authorization-gated action newly succeeds. Presence and editability are not privilege.

## Chains to

- `oauth` (3 shared chain(s))

---
Full class document: `skills/Web/authn/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authn`
