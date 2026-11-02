# Directory enumeration to SPN enumeration to kerberoasted service account to lateral execution

> goal: `domain_wide_lateral_movement`
> generated from `db/wks.db` — edit the rows, not this file

Directory enumeration filtered to SPN-bearing accounts supplies exactly the input kerberoasting needs, and the recovered service-account password becomes an authenticated remote-execution channel across hosts the enumeration never touched.

## Impact

Domain-wide lateral movement and vertical escalation from a single low-privileged directory read, with no further exploitation required once the password is recovered offline.

## Sequence

### 1. Establish which hosts hold directory services and management roles so the enumeration is aimed rather than sprayed across the estate.

**Why it works:** Naming and addressing patterns predict host role inside an enterprise, so the enumeration target list comes from inference rather than a blind sweep of every address.

**Backed by:** `internal_recon.technique.private_address_space_predicts_host_role`

**This step fails if:** If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.

### 2. Enumerate domain accounts from the low-privileged session and retain the full account list.

**Why it works:** The account list is the raw material; the SPN filter applied to it is what selects the kerberoastable subset, so the unfiltered read must come first.

**Backed by:** `ad_enumeration.technique.ldap_domain_account_discovery`

**This step fails if:** If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.

### 3. Filter the enumeration output to accounts carrying servicePrincipalName, request TGS tickets with weakened encryption for each, and crack them offline.

**Why it works:** The tickets are encrypted with the NTLM hash of the account's plaintext password, so cracking them offline yields the service account password with no further network activity and no lockout exposure.

**Backed by:** `info_disclosure.chain_link.enum_to_spn_kerberoast`

**This step fails if:** If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.

### 4. Apply the recovered service-account password to whichever remote access protocols the target actually presents, such as SMB administrative shares, WinRM, or RDP.

**Why it works:** The password is an ordinary credential for every service that authenticates it, so each reachable protocol becomes an authenticated execution channel the enumeration never named.

**Backed by:** `lateral_movement.technique.remote_service_choice_is_protocol_selection`

**This step fails if:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
