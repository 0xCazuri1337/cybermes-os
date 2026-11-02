# OAuth redirect_uri validation failure to account takeover

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

When the authorization server's redirect_uri check is a prefix or substring match rather than an exact origin match, an attacker who controls any path on an allowed host can receive the authorization code and complete the flow themselves.

## Impact

Full account takeover of any user who follows a crafted authorize link.

## Sequence

### 1. Obtain the live authorize endpoint and its exact accepted parameters

**Why it works:** The redirect_uri check can only be probed once the real endpoint and its registered values are known.

**Backed by:** `oauth.prereq.authorize_endpoint_live`

**This step fails if:** No authorization request with OAuth-specific query parameters appears anywhere in the flow; login is plain password/OIDC-less form auth.

### 2. Determine whether the client is public (no secret) and whether PKCE is enforced

**Why it works:** A public client without PKCE means an intercepted code is redeemable by anyone, so the redirect_uri weakness is fully exploitable rather than theoretical.

**Backed by:** `oauth.signal.implicit_grant_or_leaked_secret`

**This step fails if:** response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.

### 3. Test redirect_uri variants and reject any that is not accepted: subdomain, suffix, path traversal and encoded forms

**Why it works:** Establishing the check is exact is what separates a real bypass from a test that merely looked unusual; most false positives here are a URL that was rejected correctly.

**Requires:** an allowed host with an attacker-writable path or subdomain

**Backed by:** `oauth.fp.redirect_host_exact_match`

**This step fails if:** A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.

### 4. Complete the authorization code flow end to end with an attacker account and show the victim's session binding to the attacker's identity

**Why it works:** Only a completed flow proves takeover; a redirected code alone shows misconfiguration, not impact.

**Requires:** an attacker-controlled account

**Backed by:** `oauth.validation.account_takeover_proof`

**This step fails if:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
