# User-consented scope to durable refresh-token principal

> goal: `data_exposure`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Register an application requesting user-consentable scopes such as mail.read or offline_access, the consent surface authz.chain_link.app_service_identity_hands_broader_scope_to_cloud_link describes as the ambient application authority

**Why it works:** Permissions scoped to what is necessary for it to function is the control; overly broad high-risk scopes are the failure, and the requesting application sets that breadth

**Requires:** Ability to publish an application registration

### 2. Induce an ordinary user to consent, which requires no administrator involvement for user-consentable scopes

**Why it works:** User-consentable scopes such as mail.read, offline_access can be consented by the user while admin-consent-required scopes cannot, so account class is the gating variable

**Requires:** The application from step 1

### 3. Obtain a refresh token via the offline_access grant and persist access beyond the originating session

**Why it works:** Consent governs whether the app can receive an authorization code and what scopes are permitted, and offline_access converts that one-time grant into durable standing access

**Requires:** The granted scopes from step 2

### 4. Read data continuously as the application principal with no further user interaction

**Why it works:** The application is authorized to act on behalf of the signed-in user constrained only by the consented scopes, so repeated access needs no new approval

**Requires:** The durable token from step 3
