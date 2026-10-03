# SSRF metadata credential theft to application identity scope

> goal: `cloud_credential_theft`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Reach a server-side fetch primitive that takes an attacker-influenced URL, the base requirement of ssrf.chain_link.scheme_abuse_file_gopher_dict

**Why it works:** The server performs the request from its own trusted network position, so the attacker inherits that position rather than needing to route traffic himself

**Requires:** An endpoint that fetches a caller-supplied URL

### 2. Bypass the fetch validator with URL-parsing confusion so the request reaches the cloud metadata service, as the Red Agent case did with authority confusion against the url parameter

**Why it works:** A validator can see one host while the fetcher connects to another, so filter bypass is a parser-differential problem rather than an allowlist problem

**Requires:** The step 1 fetch primitive and an observed validator

### 3. Read the returned credentials, which ssrf.chain_link.scheme_abuse_file_gopher_dict escalates into local file access or arbitrary-protocol access

**Why it works:** Querying cloud metadata endpoints to extract credentials, or even reading local files using alternative uri schemes, is the documented effect of that fetch primitive

**Requires:** Successful metadata reachability from step 2

### 4. Spend the credentials with the scope the hosting application identity already carries, which is the escalation authz.chain_link.app_service_identity_hands_broader_scope_to_cloud_link records

**Why it works:** Compromise of an internet-facing web application hands the next link whatever cloud scope that application identity carries, so the harvest inherits the app authority

**Requires:** The credentials from step 3 and knowledge of the bound identity
