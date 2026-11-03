# Zone transfer internal names to subdomain takeover

> goal: `infrastructure_takeover`
> generated from `db/wks.db` — edit the rows, not this file

Names recovered only by an AXFR are checked for dangling DNS records, and any name still pointing at a de-provisioned third-party service becomes an attacker-controlled host inside the target domain.

## Impact

The value is coverage rather than severity of the primitive: the takeover search normally runs over names visible in certificates and archives, and the transfer supplies the names those sources never carried, so every additional zone owner is an additional candidate for an attacker-controlled origin that inherits the target's trust.

## Sequence

### 1. Enumerate NS and SOA for the zone and attempt a transfer from every authoritative server, which is the precondition behind dns_enum.validation.serial_and_secondary_cross_check_confirms_a_real_disclosure.

**Why it works:** The transfer is of an entire zone and secondaries are meant to poll when the serial increases, so success returns every owner name rather than the subset the public records expose.

**Requires:** Authorised DNS enumeration scope for the domain

### 2. Subtract every record obtainable through NS, SOA, MX, TXT and service-record queries, and keep only the owner names that appear in the transfer alone.

**Why it works:** Only names the public surface concealed carry new attack surface; a transfer returning nothing beyond the public set adds no candidates.

**Requires:** A completed public record sweep for comparison

### 3. Resolve each recovered name and probe the target for an unclaimed or de-provisioned third-party service fingerprint, following the dangling record to a vendor endpoint that no longer provisions for it.

**Why it works:** The record outlives the service behind it, and attackers abuse the trust of the still-registered owner name rather than of the expired domain.

**Requires:** Out-of-band HTTP probes against each recovered hostname

### 4. Claim the abandoned service so the recovered hostname serves attacker content, then test whether any session cookie's Domain attribute covers that host.

**Why it works:** A host serving attacker content inside the target's own domain inherits the trust users extend to that domain, which is what turns an infrastructure foothold into session theft.

**Requires:** A dangling record confirmed claimable and a cookie scope test
