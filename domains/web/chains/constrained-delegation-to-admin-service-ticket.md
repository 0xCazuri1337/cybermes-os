# Constrained delegation to administrator service ticket

> goal: `privilege_escalation`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Compromise a user or computer account that carries Kerberos constrained delegation

**Why it works:** The delegation bit is what turns a normal host compromise into an impersonation primitive, so it is the whole precondition

**Requires:** Execution or credential access on a delegating principal

### 2. Perform the S4U2Self exchange to obtain a TGT for a chosen target identity rather than for the compromised principal

**Why it works:** The service fills out the pa_for_user data structure containing the information about the user on whose behalf it requests the ticket, so identity becomes a parameter

**Requires:** The delegating principal from step 1

### 3. Use S4U2Proxy to request a service ticket for the SPN the principal is trusted to delegate to, carrying the impersonated identity

**Why it works:** The service ticket will be sent back to the service and its PAC reflects the borrowed user rather than the real caller

**Requires:** The step 2 TGT and the known trusted SPN

### 4. Present the resulting service ticket to the delegated backend as the impersonated administrator, which is the lateral movement pass_the_hash.chain_link.dumped_ntlm_hands_authenticated_channel_to_lateral_link generalises to ticket-based authentication

**Why it works:** The backend sees a valid service ticket for a legitimate administrator and cannot distinguish the delegation from an interactive logon

**Requires:** The forged service ticket from step 3
