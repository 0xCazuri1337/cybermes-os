# dns_enum: observe, exercise, confirm

> goal: `Establish, exercise and confirm a dns_enum condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for dns_enum. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a dns_enum condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Validation: enumeration tools list an attempt to transfer a DNS zone as a module, and separately list subdomain enumeration by NSEC-walking, TXT record inspection, and reference hunting in page...

**Requires:** an authorised target with a reachable surface for dns_enum, and permission to record responses

**Backed by:** `dns_enum.validation.refused_zone_transfer_is_not_enumeration_evidence`

**This step fails if:** The transfer or an equivalent anonymous read returns an actual record set beyond SOA and NS, or an NSEC chain yields NXDOMAIN proofs for names that resolve elsewhere, showing records were retrieved without authentication.

### 2. Exercise it against the target and capture the raw request and response: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the correct behaviour.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `dns_enum.prerequisite.axfr_attempt_is_expected_only_where_a_secondary_is_configured`

**This step fails if:** The claim is wrong, and a refused or silent AXFR is not a clean configuration, if the transfer succeeds from a nameserver that is not in the zone's declared secondary set, or if a secondaries-permitted ACL is missing so any address can pull the whole zone. Success from a non-secondary address is the disproof for the expectation claim; but note that refusal from a genuinely non-secondary server does prove the zone is closed for that host, so the expectation still holds there.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those names are the ones...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `dns_enum.chain_link.zone_transfer_internal_names_to_subdomain_takeover`

**This step fails if:** The chain is refuted if the zone transfer is refused or returns nothing beyond the public NS and SOA set, leaving no name the certificate sources missed; or if every transferred name resolves to an active, correctly provisioned service, so nothing is claimable; or if the recovered internal names sit outside the registrable domain and therefore outside any session cookie's Domain scope, making a takeover phishing-only rather than session-affecting. The transfer must produce at least one live dangling record for the chain to end anywhere.
