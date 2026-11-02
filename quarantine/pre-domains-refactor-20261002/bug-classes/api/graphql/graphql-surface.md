# GraphQL-Specific Attack Surface

## Definition

A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.

- **CWE:** CWE-1004
- **OWASP:** API8:2023
- **Surface:** api
- **Aliases:** ["graphql", "graphql introspection", "graphql batching", "alias overload", "graphql injection", "deeply nested query dos"]

Canonical home for `graphql`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Unauthenticated introspection on the production GraphQL endpoint is the precondition that converts one endpoint into a full map of queries, mutations and private fields.**

Probe {"query":"{__schema{queryType{name}}}"}. If names come back unauthenticated in production, immediately dump __schema.types with descriptions; internal and admin-only types routinely survive in schemas. Most implementations ship introspection enabled and unauthenticated, so treat a live prod introspection probe as the green light for schema-driven testing.

*Disproof:* The probe returns "Introspection is disabled" or an authorization error, and no type, query or mutation names appear in the response body.

**An attackable GraphQL surface is a single path (usually /graphql) that accepts a POST body with a JSON {"query": ...} document and serves every operation type.**

Hunt: POST {"query":"query{__typename}"} to /graphql, /api/graphql, /graphql/api, /graphql/graphql, /api, then /v1 variants. A hit returns {"data":{"__typename":"query"}}. Because one endpoint serves queries and mutations alike, mapping it once exposes the whole API surface, so no other recon is worth doing until this lands.

*Disproof:* Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.

## Attack Surface

Surface: **api**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A node(id:) or nodes(ids:) field on the root Query type means any object can be fetched by global ID without traversing its parent resolver.**

Check the Query type: cat schema.json | jq '.data.__schema.types[] | select(.name=="Query") | .fields[] | .name' | grep node. Relay-style global IDs are base64("Type:id"), so base64 -d on any ID captured from a UI response exposes the sequential numeric id to feed straight back into node(id: "VXNlcjox"). Presence of this field plus sequential ids is the setup for enumeration.

*Disproof:* No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.

**A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.**

Keep two recon primitives: query{__typename} to confirm the service, and {"query":"{__schema{queryType{name}}}"} plus {__type(name:"User"){fields{name}}} to confirm schema reachability. A non-GraphQL route typically answers 404, HTML, or a generic JSON error, which tells you the endpoint guess was wrong rather than the API being hardened.

*Disproof:* Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.

## Exploitation

**Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.**

Send query isValidDiscount($c:Int){ a:isValidDiscount(code:$c){valid} b:isValidDiscount(code:$c){valid} ... } with a different $c per alias, or a body of [{"query":...},{"query":...}]. OWASP notes proxies and gateways relying on the raw number of requests will let this through, and that tooling sees one request rather than many.

*Disproof:* The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.

**A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.**

Build depth N: query evil { album(id:42) { songs { album { songs { album { id } } } } } }. Or request amount: { author(id:"abc") { posts(first: 99999999) { title } } }. GraphQL has no native depth or amount limiting - the missing limit is the finding, not merely the slow response.

*Disproof:* The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.

## Variations

**Authorization applied only in the frontend selection set is bypassed by requesting the hidden field directly, because the resolver returns it regardless of who asked.**

Diff what the UI sends (user { id name }) against your request (user { id name email role }): same response minus the hidden fields proves the UI is filtering. Aliasing that field under a new name, and replaying an allow-listed persisted-query hash over GET ?query=... or GET ?extensions=..., reaches the same resolver through a path the client never uses.

*Disproof:* The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `graphql-exposure-to-enumeration` — GraphQL excessive exposure to account enumeration to mass assignment (goal: `data_exposure`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.**

Inspect data versus errors per alias: 'Cannot query field ...' or 'Variable $c of type Int was provided invalid value' means zero resolver executions, so the amplification never ran. For resource exhaustion, retest on production; a hang on staging with a smaller dataset is not a production availability bug, and an infra-level timeout that still returns a response caps the impact.

*Disproof:* Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.

**Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.**

If {"query":"{__schema{types{name}}}"} returns introspection-disabled but a typo like { userInf { id } } answers 'Did you mean userInfo?', you are hitting the suggestions feature, not introspection. Clairvoyance automates recovery this way. Downgrade the report: partial name disclosure, no schema graph, no private field dump.

*Disproof:* The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
**Hypothesis:** A deeply nested GraphQL query caused a denial of service
- Invalidated by: The 502 came from a staging host with no rate limiting; the production instance returned 200 in under 300ms for the identical query
- **Rejection rule:** A DoS reproduced only on dev/staging is not a production finding; confirm the hostname is in scope and behaviour differs before reporting

**Hypothesis:** Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.
- Invalidated by: Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
- **Rejection rule:** Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.

**Hypothesis:** Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
- Invalidated by: The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
- **Rejection rule:** Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.

## Validation

**Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.**

Create userA and userB, create an object owned by B, then query it as A: query { product(id: 3) { id name listed } } or user(id: bId){...}. Sequential ids plus a populated response from the wrong session is BOLA/IDOR - OWASP names the missing object-level authorization check as the core ingredient, not an unguessable id.

*Disproof:* The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.

**Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.**

Baseline: issue isValidDiscount 5 times sequentially and note where 429 starts. Then send one request with 100 aliased calls (or a 100-element JSON array) and show all 100 land with no 429, because the limiter counted a single HTTP request. Observable side effects such as created rows beat a bare valid:true in the proof.

*Disproof:* The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.

## Impact

**A resolver that interpolates a string argument into a downstream SQL or HTTP call turns a plain GraphQL query into injection with server-side privileges.**

Hunt String-typed args (search, filter, slug) that reach raw SQL or an outbound fetch: { search(term: "' OR '1'='1") { id } }. OWASP notes user identifiers flow into HTTP requests, DB queries, and other calls, which is the injection opportunity. Impact escalates past schema disclosure to full DB read/write or internal service access.

*Disproof:* Quote or bind parameters handle the argument, the endpoint rejects metacharacters, and payloads produce ordinary empty result sets with no behavioural difference.

## Related Bug Classes

Not yet researched.

## References

- **api-security.owasp.org** (taxonomy)
  - <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
- **portswigger.net** (taxonomy)
  - <https://portswigger.net/web-security/graphql>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
