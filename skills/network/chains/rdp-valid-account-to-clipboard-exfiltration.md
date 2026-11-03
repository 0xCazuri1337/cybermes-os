# Valid-account RDP logon to clipboard and drive data exfiltration

> goal: `Use a credential obtained elsewhere in the environment to establish an RDP session and move data off the target through the protocol's own redirection channels, without deploying an exfiltration agent.`
> generated from `db/wks.db` — edit the rows, not this file

RDP authenticates with a known credential and then provides clipboard and drive redirection in both directions, so one interactive logon is sufficient to read and remove data.

## Impact

Collection of any data the logged-on user can read, exfiltrated in interactive-sized chunks that resemble normal remote administration.

## Sequence

### 1. Reuse a credential harvested elsewhere against a host where the RDP service is enabled and accepts it.

**Why it works:** MITRE states adversaries may connect over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials, so no exploit is required for this step.

**Backed by:** `rdp.technique.known_credentials_plus_enabled_service_is_the_whole_prerequisite`

**This step fails if:** The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.

### 2. Read data through the session and copy it out via clipboard mapping, or read the client drive exposed to the remote session.

**Why it works:** Microsoft documents that users can delete, copy, and paste text and graphics between local and remote applications and between sessions, and that local client drives will be visible to the remote desktop session, so the protocol itself carries the data out.

**Backed by:** `rdp.technique.clipboard_and_drive_redirection_carries_data_off_host`

**This step fails if:** The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.
