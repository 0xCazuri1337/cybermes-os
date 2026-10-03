# Dangling NS delegation to transitive zone compromise

> goal: `infrastructure_takeover`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Identify an NS record whose authoritative name server has been de-provisioned, the dangling delegation case studied alongside CNAME records

**Why it works:** An NS record delegates to an authoritative name server, so an unreleased delegation leaves the zone pointing at infrastructure nobody operates

**Requires:** Authoritative DNS data for the zone

### 2. Claim the de-provisioned name server so the delegation resolves to attacker infrastructure

**Why it works:** Registration of the vacated endpoint is enough, because the zone record continues to delegate to it

**Requires:** The dangling delegation from step 1

### 3. Inherit the transitive trust DNS confers, expanding impact beyond the delegated subdomain

**Why it works:** The transitive trust built into DNS could make all domains that directly or indirectly depend on the dangling NS record vulnerable

**Requires:** Step 2 control of the delegated server

### 4. Reach the apex zone where the delegation chain terminates, which is the impact boundary Detectify flags as exceeding even critical injection bugs

**Why it works:** An attacker getting control of one out of many name server delegations for the root apex zone can make the outcome worse than the most critical form of SQL injection

**Requires:** The expanded transitive trust from step 3
