# ad_ldap: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ad_ldap condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ad_ldap. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ad_ldap condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation that triggers this false positive is a directory dump that returns a large, plausible Active Directory object graph from a host an operator assumed was just another LDAP listener on...

**Requires:** an authorised target with a reachable surface for ad_ldap, and permission to record responses

**Backed by:** `ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones`

**This step fails if:** A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.

### 2. Exercise it against the target and capture the raw request and response: An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ad_ldap.technique.filter_syntax_is_attacker_reachable_structure`

**This step fails if:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ad_ldap.fp_rule.anonymous_ldap_read_is_default_ad_configuration`

**This step fails if:** The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.
