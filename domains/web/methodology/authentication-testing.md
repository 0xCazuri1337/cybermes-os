# Authentication testing

Procedure for the authentication boundary. Classes live in
[`bug-classes/web/authentication/`](../areas/web/authentication/README.md).

## Order

1. **Establish the mechanism first** — password, token, session, or federated.
   Every later test depends on which one it is.
2. **The login path** — rate limiting, lockout, and user enumeration through
   response *differences* rather than status alone.
3. **The session path** — fixation, invalidation on privilege change, and
   whether logout actually revokes server-side.
4. **The second factor** — enforced per session, per request, or only at login.
   The first two differ materially.
5. **Token validation** — signature, algorithm and claims, if tokens are used.
6. **Recovery last** — it replaces the login check and is usually the weakest
   link in the chain.

## Disproof for each step

A test that cannot fail proves nothing. Each class file's *Preconditions*
section states what would disprove the hypothesis — for recovery, typically
that the reset token is single-use, bound to the requester, and short-lived.

## Related

- [authorization.md](authorization.md) — the next boundary
- [authentication-chains.md](../chains/authentication-chains.md)
- [evidence-requirements.md](../../../validation/evidence-requirements.md)