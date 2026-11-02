# Dangling DNS record to session cookie theft

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Enumerate DNS records whose target service has been de-provisioned, which is the dangling-record precondition behind subdomain_takeover.chain_link.session_cookie_domain_scope_to_attacker_host

**Why it works:** In dangling domain hijacking the attackers instead abuse the trust of the unexpired rrname, so the record outlives the service and keeps resolving

**Requires:** Asset inventory plus DNS record data

### 2. Claim the abandoned third-party target so the attacker can serve arbitrary content on a hostname inside the target's own domain

**Why it works:** A subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target because the DNS record was not properly de-provisioned

**Requires:** The dangling record from step 1

### 3. Harvest the session cookie of a user who visits the taken-over host, exploiting the Domain-attribute precondition stated in subdomain_takeover.chain_link.session_cookie_domain_scope_to_attacker_host

**Why it works:** The takeover is usually only considered severe if it compromises other systems or gives direct access to user data such as cookies, which is exactly what a broadly scoped cookie attribute permits

**Requires:** Step 2 origin plus a cookie whose Domain covers that host

### 4. Replay the captured cookie against the real application to act as the victim inside the authenticated session

**Why it works:** The cookie is the session credential itself, so replay needs no further exploit once it has been read

**Requires:** The session cookie from step 3
