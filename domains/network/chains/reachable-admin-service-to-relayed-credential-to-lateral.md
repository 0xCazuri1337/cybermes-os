# Policy-violating administrative service reachability to relayed server credentials to lateral movement

> goal: `credential_theft_and_lateral`
> generated from `db/wks.db` — edit the rows, not this file

An administrative service reachable from a forbidden segment concedes its authentication surface to that reachability, and once it answers a coerced or relayed authentication it hands over a credential that becomes the next protocol's authenticated channel.

## Impact

Credential theft for a service account plus authenticated remote execution on the next host, reachable from a network position that was never meant to expose an administrative surface.

## Sequence

### 1. Establish from an untrusted source network that the administrative protocol answers, completing the handshake and reaching a login prompt without any credential.

**Why it works:** An administrative or remote service reachable from where policy forbids it concedes its authentication surface to that reachability; without the reachability there is nothing to relay and the chain does not start.

**Backed by:** `exposed_services.technique.external_remote_service_is_initial_access`

**This step fails if:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.

### 2. Confirm the exposed management surface is an expected property of the asset class rather than a one-off misconfiguration, and record which protocols it offers.

**Why it works:** Internet-facing building management and CPS devices commonly ship with remote access and open ports, so the exposure's prevalence and the authentication mechanisms it offers determine whether the relay branch is even available.

**Backed by:** `exposed_services.prerequisite.remote_access_and_open_ports_on_cp_s_assets`

**This step fails if:** An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.

### 3. Coerce the reachable service into an outbound authentication to an attacker-controlled listener and capture the returned NTLM response.

**Why it works:** A server that initiates an outbound SMB connect to an attacker-chosen host will answer that host's challenge with its own NTLM credentials, converting unauthenticated reachability into a relayable credential with no password held.

**Backed by:** `smb.chain_link.force_auth_hands_relayable_ntlm_to_relay_link`

**This step fails if:** If SMB signing is mandatory on the first connection, or the target refuses outbound SMB to untrusted peers, or channel binding pins the second service to a TLS channel the attacker does not hold, no NTLM response is emitted or accepted and the relay link has nothing to work with.

### 4. Replay the captured response against the next authentication surface and confirm whether signing or channel binding is enforced on that second service.

**Why it works:** The relayed credential is only useful where it is replayable; the differential signing state bounds the relay ceiling and decides whether the chain ends at credential theft or reaches authenticated remote execution.

**Backed by:** `lateral_movement.technique.remote_service_choice_is_protocol_selection`

**This step fails if:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
