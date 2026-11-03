# IDOR on a password/session object to account takeover

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

An object-level authorization flaw on an endpoint that returns or mutates authentication material is a full account takeover rather than an information leak, because the disclosed object IS the credential.

## Impact

Complete compromise of arbitrary user accounts; password reset on any user by writing the reset object belonging to them.

## Sequence

### 1. Locate an endpoint whose path or body carries a client-supplied object identifier for an authentication-adjacent resource

**Why it works:** Every later step requires an identifier the client chooses; without one there is no object to enumerate.

**Requires:** an endpoint referencing a password reset, session, refresh token, email change or MFA record by id

**Backed by:** `idor.prereq.client_controlled_object_identifier`

**This step fails if:** Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.

### 2. Swap that identifier for one belonging to another account and record what comes back

**Why it works:** If the server does not re-check ownership per object, the response carries the other account's data.

**Requires:** two accounts you control

**Backed by:** `idor.technique.swap_identifier_all_carriers`

**This step fails if:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.

### 3. Confirm the read crosses the tenant boundary using your own two accounts, capturing both responses side by side

**Why it works:** Reading your own second account proves the authorization boundary is missing without involving anyone but yourself — this is what makes the finding reportable rather than theoretical.

**Requires:** two accounts with distinct data

**Backed by:** `idor.validation.two_account_cross_tenant_read`

**This step fails if:** As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.

### 4. Escalate the read into a write: attempt to change the reset token, email or MFA state on the object you reached

**Why it works:** A read that crosses tenants is often the same missing check on the mutating verb; if it holds, the leak becomes takeover.

**Backed by:** `idor.chain_link.to_account_takeover_and_privesc`

**This step fails if:** The exposed object contains no credential, token, session or role-bearing field, and no writable endpoint accepts an ownership or privilege field from the client.
