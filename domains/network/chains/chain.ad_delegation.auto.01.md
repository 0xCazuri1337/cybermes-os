# ad_delegation: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ad_delegation condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ad_delegation. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ad_delegation condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: When a write-capable principal can set msDS-AllowedToDelegateTo on a host or service account, the attacker can request a service ticket for any principal to the listed SPN and present it to that resource, so the delegated hop ends in code execution as SYSTEM...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Previous primitive hands over: write access to the delegation attribute on a directory object (GenericWrite/GenericAll on the computer or service account, or SeEnableDelegation on the domain). The...

**Requires:** an authorised target with a reachable surface for ad_delegation, and permission to record responses

**Backed by:** `ad_delegation.chain_link.rbcd_ticket_forward_hands_system_shell_to_next_link`

**This step fails if:** A KDC that refuses the s4u TGS-REQ for a target outside the delegating account's own SPN list, or a resource service that rejects a ticket without EPA/channel binding, breaks this segment; so does a directory where no principal other than domain admins can write msDS-AllowedToDelegateTo.

### 2. Exercise it against the target and capture the raw request and response: A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ad_delegation.chain_link.constrained_delegation_any_user_impersonation`

**This step fails if:** Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ad_delegation.technique.delegated_ticket_replay`

**This step fails if:** If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
