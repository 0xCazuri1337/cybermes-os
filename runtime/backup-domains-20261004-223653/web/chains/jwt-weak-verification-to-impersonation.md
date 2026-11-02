# jwt-weak-verification-to-impersonation

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

A token flaw that lets an attacker influence or bypass signature verification is combined with a predictable or disclosed subject identifier to mint a token the server accepts as another user.

## Impact

The attacker authenticates as an arbitrary account, inheriting that user's sessions, data and any administrative privileges attached to the role.

## Sequence

### 1. Establish the token's verification behaviour with a negative control: send a request with no token, with a malformed token, and with a well-formed token signed by a key you control, and record which of the three produce a different response.

**Why it works:** Only the requests whose responses differ are governed by token validation. Without this control every later observation may come from a route that was never protected, which is the most common way a JWT finding turns out to be nothing.

**Requires:** a protected endpoint that visibly differs between authenticated and unauthenticated callers

### 2. Identify the trust anchor the server actually uses: a fixed key, a key selected by the kid or jku header, a per-user key, or a session store that overrides the presented claims.

**Why it works:** The trust anchor determines the attack. A remote kid or jku that the server fetches is a different vulnerability from a hardcoded weak secret, and a session-store design means claim tampering has no effect at all - the presented token is only an identifier.

**Requires:** the ability to compare two tokens that differ only in the header field under test

### 3. Exploit the trust anchor: if the secret is weak or guessable, forge a token; if the key is selected by a header, supply your own key; if verification is skipped for a code path, omit the signature entirely.

**Why it works:** This converts a parsing weakness into a signing capability, which is the precondition for impersonation. The forged token must be accepted by the same verification path a legitimate token takes.

**Requires:** control over the key material, the secret, or the algorithm the server will accept

### 4. Set the subject or user identifier claim to a target account, discovering the identifier format from the application's own responses, and confirm the server reissues a session bound to that identity.

**Why it works:** A forged token is only useful if the server attributes it to someone. Proving the reissued session resolves to the target's data, rather than merely returning a 200, is what separates a real impersonation from a parsing curiosity.

**Requires:** knowledge of the claim that carries identity, and an endpoint that returns target-specific data
