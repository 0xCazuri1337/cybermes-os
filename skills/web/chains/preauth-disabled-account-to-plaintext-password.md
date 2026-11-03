# Pre-authentication-disabled account to plaintext password

> goal: `credential_access`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Identify users carrying the Do not require Kerberos preauthentication flag during directory enumeration

**Why it works:** AS-REP roasting targets exactly the accounts whose Kerberos preauthentication property is not set, so enumeration defines the target set precisely

**Requires:** Authenticated domain user context

### 2. Send an AS-REQ for each flagged account and capture the AS-REP returned in place of a pre-authentication exchange

**Why it works:** Without preauthentication the KDC issues the TGT immediately, so no valid password is needed to reach the encrypted blob

**Requires:** The flagged-account list from step 1

### 3. Extract the AS-REP portion encrypted under the user's NTLM hash

**Why it works:** The TGTS are encrypted with the user's NTLM hash, so the hash is the sole key protecting the response

**Requires:** The AS-REP from step 2

### 4. Crack the extracted portion offline and reuse the plaintext password, which is the credential pass_the_hash.chain_link.dumped_ntlm_hands_authenticated_channel_to_lateral_link then turns into authenticated lateral access

**Why it works:** Those hashes can then be cracked offline, similarly to how it is done in kerberoasting, so no failed logon is ever generated

**Requires:** The encrypted response from step 3
