# SPN enumeration to offline service account hash recovery

> goal: `credential_access`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Enumerate accounts carrying a serviceprincipalname, which is the target-selection step that ad_delegation.chain_link.unconstrained_delegation_replay_hands_hash_to_credential_access shares with the broader credential-discovery family

**Why it works:** In Active Directory, service accounts used to run applications and services have associated service principal names, and those names are the request targets

**Requires:** Any authenticated domain user context

### 2. Request a TGS for each discovered SPN without knowledge of the service account password

**Why it works:** Kerberoasting is an attack exploiting how Kerberos tickets are encrypted in AD, allowing attackers to crack service account passwords offline at high speed

**Requires:** The SPN list from step 1

### 3. Extract the ticket portion encrypted under the service account NTLM hash

**Why it works:** When a Kerberos ticket is issued it contains a portion encrypted with the service account NTLM hash, which is the only secret protecting that portion

**Requires:** The TGS responses from step 2

### 4. Crack the extracted portion offline and reuse the recovered password, feeding pass_the_hash.chain_link.dumped_ntlm_hands_authenticated_channel_to_lateral_link

**Why it works:** Cracking happens even faster when the account encryption is set to RC4, and the resulting hash authenticates to every NTLM-accepting service in reach

**Requires:** The encrypted ticket portion from step 3
