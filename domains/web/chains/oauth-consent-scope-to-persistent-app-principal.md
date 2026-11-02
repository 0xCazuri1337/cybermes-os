# OAuth consent scope capture to persistent application principal

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Obtain an authorization code by inducing or intercepting consent on the authorize endpoint, the precondition described by open_redirect.chain_link.oauth_authorize_code_interception

**Why it works:** If redirect_uri is accepted from user input rather than an allowlist, the code can be delivered to an attacker endpoint during a legitimate-looking consent

**Requires:** A client whose authorize step reflects an attacker-influenced redirect_uri

### 2. Redeem the code for a token whose scopes are whatever the consent granted rather than what the application strictly needs

**Why it works:** Consent governs whether the app can receive an authorization code and what scopes are permitted, so scope breadth is decided at consent and persists in the token

**Requires:** The intercepted authorization code

### 3. Use the token as a durable application principal, turning a single consent event into standing access as recorded in authz.chain_link.app_service_identity_hands_broader_scope_to_cloud_link

**Why it works:** OAuth applications in Entra ID are a common persistence mechanism precisely because the granted scope keeps working after the originating session ends

**Requires:** A redeemable token with granted scopes

### 4. Escalate from the consented identity to a forged or replayed credential for the same account, which jwt.chain_link.forgery_to_account_takeover describes as the outcome when a token drives server-side identity decisions

**Why it works:** Only when the edited or replayed claim drives authorization decisions does a verified forgery become takeover rather than disclosure

**Requires:** The standing application principal from step 3
