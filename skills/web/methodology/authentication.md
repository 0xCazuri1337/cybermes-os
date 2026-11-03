# Methodology — Authentication

> Generated 2026-10-01T18:41:23Z. Competency id: `authentication`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Establishing who the system believes you are, and every way that belief can be forged, borrowed, or confused.

## Procedure

 1. **Map the mechanisms** — Sessions, JWT, API keys, OAuth/OIDC, SAML, magic links, and remember-me. Note where each
is validated.
 2. **Inspect the token** — Algorithm, claims, expiry, signature verification, and whether 'none' or algorithm
confusion is possible.
 3. **Test the logout and expiry path** — Sessions that survive logout are a finding independent of any other.
 4. **Test credential handling** — Rate limiting, lockout, user enumeration through response or timing, and password reset
flow integrity.
 5. **Test recovery flows** — Reset tokens: single-use, expiring, bound to the intended account, and not sent to a
controllable channel.
 6. **Test MFA** — Whether it can be skipped by altering the post-authentication request, not only by
failing the challenge.
 7. **Check for parallel sessions** — Whether an authenticated session can be revoked.
 8. **Check the account-linking path** — Linking a second identity is an authentication bypass if ownership of the second is not
proven.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- Server-side session state is authoritative and tamper-evident.
- All recovery tokens are single-use, short-lived, and delivered to the registered channel.

## Gates before this becomes a finding

- bypass reproduced on a fresh session
- impact on the account is demonstrated, not inferred

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
