# service_enumeration: observe, exercise, confirm

> goal: `Establish, exercise and confirm a service_enumeration condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for service_enumeration. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a service_enumeration condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Enumeration is a selection step, not an end. The scan output — open ports, service banners, OS fingerprints — is what tells you whether NTLM relay, SMB signing, WinRM or an exposed RDP listener is a...

**Requires:** an authorised target with a reachable surface for service_enumeration, and permission to record responses

**Backed by:** `service_enumeration.technique.banner_selects_the_applicable_technique`

**This step fails if:** If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.

### 2. Exercise it against the target and capture the raw request and response: An open TCP port on an internet-facing host is a baseline observation, not a finding; do not file a port as a vulnerability unless a specific weakness is reachable on that port - an unauthenticated service, a default credential, or a known-vulnerable version...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `service_enumeration.fp_rule.open_port_alone_is_not_a_finding`

**This step fails if:** The service listening on the port accepts unauthenticated requests, ships a default or well-known credential, or runs a version with a known exploitable CVE - in which case the open port is the delivery path for a real, demonstrable weakness and belongs in the report as such.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `service_enumeration.validation.rdp-session-correlated-with-enumerated-rdp-rights-and-credential-origin`

**This step fails if:** Proof the claim wrong would be a session where the account holds no enumerated RDP right to the destination yet the session succeeded, or one where the credential was legitimately issued to the operator but the session still carried a non-standard channel and created a forward -- in either case rights and credential origin would not have discriminated the finding, and channel plus process evidence would have to be the deciding signal.
