# Missing OAuth state parameter to login CSRF to attacker-bound victim session

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

An absent state parameter leaves the callback unbound to the login that initiated it, so the victim's session ends up attached to the attacker's upstream identity; redirect_uri laxity is what makes the binding attacker-chosen.

## Impact

Victim actions performed and stored data written into an account the attacker controls, with the victim believing they are in their own session.

## Sequence

### 1. Complete a login with no state value stored at initiation, then complete a second with a mismatched state, and compare whether the callback is accepted either time.

**Why it works:** The state value is the client's proof that the callback belongs to the login it started; accepting a callback that was never issued for that session is the unbound-callback condition login CSRF needs.

**Backed by:** `oauth.tech.callback_csrf_missing_state`

**This step fails if:** A random, single-use state bound to the user agent is present and the callback rejects any state the client did not issue for that browser session.

### 2. Probe redirect_uri registration variants to establish whether the authorization server accepts a value outside the client's registered whitelist.

**Why it works:** A whitelist of genuine callback URIs registered with the OAuth service is the documented control; where it is absent the attacker chooses which upstream identity gets bound during the confused login.

**Backed by:** `oauth.tech.redirect_uri_manipulation`

**This step fails if:** Every mutated redirect_uri outside the exact registered string is rejected (invalid_redirect_uri / 400), Location always stays on the registered host, and no dangling subdomain exists.

### 3. Demonstrate the binding with two identities: complete the confused login as the victim, then show the resulting session resolving to the attacker's upstream account and writing victim data into it.

**Why it works:** Only a completed flow with two observed identities proves takeover; a decoded token or a bare redirect shows misconfiguration rather than the identity substitution that is the actual impact.

**Backed by:** `oauth.validation.account_takeover_proof`

**This step fails if:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
