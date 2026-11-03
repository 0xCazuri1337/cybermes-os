# winrm: observe, exercise, confirm

> goal: `Establish, exercise and confirm a winrm condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for winrm. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a winrm condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: What the primitive gives you: remote command execution inside the target's security context. Microsoft's Blackbyte case study records the actor using RDP and PowerShell remoting to obtain access to...

**Requires:** an authorised target with a reachable surface for winrm, and permission to record responses

**Backed by:** `winrm.technique.winrm_remoting_is_the_lateral_execution_channel`

**This step fails if:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.

### 2. Exercise it against the target and capture the raw request and response: WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `winrm.technique.winrm_session_is_remote_execution`

**This step fails if:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `winrm.fprule.http_listener_is_encrypted`

**This step fails if:** Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
