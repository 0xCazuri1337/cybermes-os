# subdomain_takeover: observe, exercise, confirm

> goal: `Establish, exercise and confirm a subdomain_takeover condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for subdomain_takeover. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a subdomain_takeover condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The impact ceiling of a dangling record is set by record type, and the published research separates the cases explicitly. A CNAME record specifies the canonical name of an alias domain, so hijacking...

**Requires:** an authorised target with a reachable surface for subdomain_takeover, and permission to record responses

**Backed by:** `subdomain_takeover.chain_link.dangling_ns_transitive_trust_reaches_apex_zone`

**This step fails if:** Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.

### 2. Exercise it against the target and capture the raw request and response: A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `subdomain_takeover.fp_rule.passive_list_is_a_lead_not_a_claimable_subdomain`

**This step fails if:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that sibling host.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `subdomain_takeover.chain.dangling_dns_to_session_cookie_theft`

**This step fails if:** Refuted when the affected host sits outside every session cookie's Domain attribute, or when the application binds its session to a host-only cookie; the DNS half alone is then cosmetic phishing and not session theft.
