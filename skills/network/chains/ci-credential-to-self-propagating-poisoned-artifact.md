# CI credential exposure to self-propagating poisoned artifact to re-executing host delivery

> goal: `persistent_host_execution`
> generated from `db/wks.db` — edit the rows, not this file

A CI runner or publish token supplies both the propagation primitive and the delivery stage, so one build compromise reaches hosts by installing a re-executing mechanism that host-level remediation cannot outrun.

## Impact

Persistent execution across the estate from a single build-system credential, surviving endpoint cleanup because the delivery artifact re-applies itself.

## Sequence

### 1. Establish that the build runner can reach arbitrary outbound destinations and holds credentials usable off the intended path.

**Why it works:** A runner able to reach arbitrary network destinations will hand its credentials to whatever answers, so the trust boundary is the runner's network position rather than its repository permissions.

**Backed by:** `supply_chain.signal.ci-egress-credential-exposure`

**This step fails if:** If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.

### 2. Show that the exposed credential or token can publish further upstream versions, not merely consume them.

**Why it works:** A stolen package publish token lets an attacker ship further malicious versions from the compromised account, converting one credential into unbounded downstream delivery.

**Backed by:** `supply_chain.technique.stolen-publish-token-self-propagation`

**This step fails if:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.

### 3. Confirm the delivered component acts at install time rather than embedding its logic in the primary payload.

**Why it works:** Attacks that avoid embedding malicious logic in the primary payload survive content inspection, which is why the install-time action rather than the artifact contents is the signal worth hunting.

**Backed by:** `supply_chain.signal.post_install_execution_as_delivery_stage`

**This step fails if:** Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.

### 4. Treat the installed component as an operator-session-equivalent agent on each host and assess reachability of its management interface.

**Why it works:** An agent installed by the delivery stage inherits the operator session on its host, so its management interface becomes the next hop; because the delivery mechanism re-executes on a schedule the defender does not control, endpoint cleanup alone cannot remove it.

**Backed by:** `exposed_rmm.technique.rmm_inherits_the_operator_session`

**This step fails if:** If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.
