<!-- GENERATED from db/wks.db — do not edit -->
# GraphQL-Specific Attack Surface

## Definition

A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.

- **CWE:** CWE-1004
- **OWASP:** API8:2023
- **Surface:** api
- **Aliases:** ["graphql", "graphql introspection", "graphql batching", "alias overload", "graphql injection", "deeply nested query dos"]

Canonical home for `graphql`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

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

**A node(id:) or nodes(ids:) field on the root Query type exposes a standard mechanism for asking for an object by its global ID, so the object is reachable by ID rather than only through its parent field.**

Check the Query type: cat schema.json | jq '.data.__schema.types[] | select(.name=="Query") | .fields[] | .name' | grep node. Relay-style global IDs are base64("Type:id"), so base64 -d on any ID captured from a UI response exposes the sequential numeric id to feed straight back into node(id: "VXNlcjox"). Presence of this field plus sequential ids is the setup for enumeration.

*Disproof:* No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.

**A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.**

Keep two recon primitives: query{__typename} to confirm the service, and {"query":"{__schema{queryType{name}}}"} plus {__type(name:"User"){fields{name}}} to confirm schema reachability. A non-GraphQL route typically answers 404, HTML, or a generic JSON error, which tells you the endpoint guess was wrong rather than the API being hardened.

*Disproof:* Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.

**A convincing observation for this class is: The field discipline is to read the data object, not the status code or the errors array.**

Derived from graphql.fp_rule.an_error_in_the_errors_key_is_not_a_rejected_query, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (graphql.fp_rule.an_error_in_the_errors_key_is_not_a_rejected_query) states the full boundary.

**A convincing observation for this class is: Observable side effects such as created rows beat a bare valid:true in the proof.**

Derived from graphql.validation.rate_limit_bypass_proof, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (graphql.validation.rate_limit_bypass_proof) states the full boundary.

## Exploitation

**Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.**

Send query isValidDiscount($c:Int){ a:isValidDiscount(code:$c){valid} b:isValidDiscount(code:$c){valid} ... } with a different $c per alias, or a body of [{"query":...},{"query":...}]. OWASP notes proxies and gateways relying on the raw number of requests will let this through, and that tooling sees one request rather than many.

*Disproof:* The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.

**A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.**

Build depth N: query evil { album(id:42) { songs { album { songs { album { id } } } } } }. Or request amount: { author(id:"abc") { posts(first: 99999999) { title } } }. GraphQL has no native depth or amount limiting - the missing limit is the finding, not merely the slow response.

*Disproof:* The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.

**A GraphQL API with introspection enabled in production discloses the types and operations the endpoint supports, including operations reserved for high-privilege users, and an undocumented endpoint absent from the gateway route table discloses by existing at all.**

The technique has two halves that compound. First, introspection: as Checkmarx describes it, introspection is a handy development feature that, when enabled in production, discloses the types and operations that are supported by the API, including sometimes queries and mutations that are only available to high privilege users. This is not cosmetic because schema fields often carry the names of privileged operations even when the resolver later denies access, so introspection yields a complete target list even when every call fails. The cited precedent is real: CVE-2021-4191 disclosed how GitLab's API allowed a remote, unauthenticated attacker to recover usernames, names and sometimes email addresses, because the User object type was exposed without any sort of authentication. Second, shadow APIs, endpoints existing in code but never documented or registered with the gateway, so gateway and WAF have no rule for them. Checkmarx's account of the 2022 APAC telco breach has exactly that shape: attackers scraped customer PII via an unsecured API endpoint publicly available on the internet, and an API Gateway or WAF may not have stopped it because it was unaware the endpoint existed. The hunt is to run introspection everywhere then diff the schema against the gateway route table; the difference is the shadow set.

*Disproof:* If introspection is disabled or restricted to authenticated administrators in production, or the deployment enforces field-level authorisation inside the resolver rather than at the gateway, then the schema reveals no operation the caller could not already reach by name.

## Variations

**An authorization rule declared with an explicit operations list applies only to those operations, so a filter written for READ leaves UPDATE, DELETE and AGGREGATE unguarded on the same type.**

Declarative authorization in GraphQL tends to look like a schema-level control, which invites the assumption that annotating a type protects it. The mechanism is more granular than that: rules can be scoped to specific operations - READ, AGGREGATE, UPDATE, DELETE, CREATE, CREATE_RELATIONSHIP, DELETE_RELATIONSHIP - and a rule carrying an operations list is enforced only for those. That produces a specific and easily missed finding: a type filtered for reads still accepts an update that returns the row it should not have touched. The converse trap is that omitting the operations argument means the full list applies, so a rule without the list is safe and a rule with a partial list is not - the difference is one clause. Neo4j's documentation of both behaviours makes this a concrete check: when hunting, test each operation type against a resource you do not own rather than only the query you happened to construct during recon.

*Disproof:* The claim is false when the rule has no operations argument, since the library then treats the configuration as if the full list of operations had been provided and every operation is filtered. It is also false where validation rules rather than filter rules are in force on the type, because validation throws an error instead of silently narrowing, so the same scoping mistake produces a loud denial on the unlisted operations rather than a silent data exposure. And a type whose write paths are gated by a separate directive, a resolver-level check, or a database policy is not exposed by the filter's operations list, because the filter was never the only gate.

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

**A GraphQL response containing both data and errors is a partial success, not a rejection, so a field that returned data alongside a sibling field's error has executed and its authorization decision must be evaluated on that data.**

graphql.org is explicit that field errors are raised if something unexpected happens during execution, that a resolver may raise directly or return invalid data such as a null value for a field that has a Non-Null output type, and that in these cases GraphQL will attempt to continue executing the other fields and return a partial response, with the data key appearing alongside the errors key. That kills the most common GraphQL false positive in both directions: a tester who sees a 200 with errors declares the query rejected when sibling fields actually returned data, and a tester who sees an error in one field declares the endpoint protected when the field under test is in the data block. The field discipline is to read the data object, not the status code or the errors array. A field whose resolver returned null because a check failed is a working deny; a field that returned an object is an allow, whatever the rest of the response says.

*Disproof:* The claim is false when the error is a request error rather than a field error, because those abort execution before the field resolvers run and no data key is produced - the finding then rests on the data being absent, not on the errors array being present. It also fails where a Non-Null field bubbles the null upward and erases the whole data key, which is the correct deny and must not be reported as partial success. And a response that omits the data key entirely while returning errors is a rejection under either reading, so the rule is only about reading partial responses properly.

**An API that refuses __schema introspection is not thereby protected, and a report that closes on 'introspection is disabled' is reporting the absence of one discovery channel, not the presence of authorization.**

graphql.org's own position is that disabling introspection can be used as a form of security through obscurity but will not be sufficient to entirely obscure a GraphQL API by itself, and that it may be used as part of a broader strategy to limit discoverability rather than as the control. The field consequence is that a hunter cannot use 'introspection is off' to justify skipping the endpoint: the schema is still obtainable through field-error-driven inference, through the client's own bundles and source, through any documented example operation, and through simply knowing the operation names. Note the corollary that protects honest reports - graphql.org also says APIs serving only first-party clients may legitimately forbid introspection in non-development environments, so the finding is not 'introspection is enabled', it is 'a field returned data it should not have'. Introspection on a first-party-only API is a hardening observation at most.

*Disproof:* The claim is false as a statement about a given deployment when the operation surface is genuinely closed to untrusted clients by a control outside GraphQL - an mTLS or sender-constrained client credential, a client-certificate-gated gateway, or a document allowlist that only accepts operations the server itself issued. In that architecture obscurity is a genuine layer rather than the only layer, and an unauthenticated tester genuinely cannot discover the schema. It is also false as a claim that introspection-disabled APIs are always reachable - some servers reject unknown fields entirely with a request error and no partial data, which raises the bar considerably even though it is not a formal control.
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

**A resource-exhaustion finding in GraphQL needs evidence of backend cost; depth limiting is not the only control, because a shallow operation with many aliases can amplify load in a single HTTP request.**

graphql.org separates three guards and the field test has to match the one you are actually probing. On depth: it is a good idea to limit the maximum depth of fields a single operation can have, and because nesting list fields can result in exponential increases to the amount of data returned it recommends a separate smaller limit on list nesting. On breadth: the guidance gives the alias case concretely - a query selecting friends1 through friends100 is shallow, yet the underlying data source still has to handle a large number of requests to resolve data for the aliased field - and it adds that there should be an upper limit on the total number of queries in a single batch. On rate limiting: depth, breadth and batch limiting prevent categories of malicious operation but do not provide a way to declare that a particular field is expensive. So the convincing evidence for exhaustion is a measured increase in backend work or latency for a small document, not a document that merely looks large.

*Disproof:* The claim does not hold when the server enforces a document allowlist or trusted documents, because an operation the attacker cannot author cannot carry a hundred aliases or a deep list nest, and the amplification is structurally unavailable. It also fails where the API enforces field-level pagination with a server-side maximum page size, because the aliased-query cost is then bounded per alias regardless of how many aliases appear. And a finding needs a measured delta - a 200 response to a large document proves only that the document was accepted, not that it cost anything, so a purely qualitative large-query report is not the evidence this rule asks for.

**Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.**

Create userA and userB, create an object owned by B, then query it as A: query { product(id: 3) { id name listed } } or user(id: bId){...}. Sequential ids plus a populated response from the wrong session is BOLA/IDOR - OWASP names the missing object-level authorization check as the core ingredient, not an unguessable id.

*Disproof:* The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.

**Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.**

Baseline: issue isValidDiscount 5 times sequentially and note where 429 starts. Then send one request with 100 aliased calls (or a 100-element JSON array) and show all 100 land with no 429, because the limiter counted a single HTTP request. Observable side effects such as created rows beat a bare valid:true in the proof.

*Disproof:* The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.

**Authorization applied only where the frontend happens to select the field is bypassed when the same field, requested directly in a hand-built operation with no frontend involvement, returns the value the UI suppresses - a populated object rather than null or an error.**

Determine what the real client selects: capture one genuine query from the application, note the field set it requests, and identify fields present in the type but absent from every captured selection set - internal flags, ownerId, tenantId, isAdmin, moderationState, costPrice. For each such field, issue a minimal operation from an authenticated low-privilege account that selects only that field on an object the account owns or can reach, with no sibling fields and no fragments. Read the data object for that key. The pass condition is a non-null value that the account's role should not see, reproduced on a second object of the same type so the result is not a per-record fluke. The decisive contrast is the paired request: select the field the UI does request alongside the hidden one in the same operation and show that the hidden field's value differs in sensitivity while the operation returns 200. If the hidden field returns null, or an errors entry naming an authorization failure, or is absent from the type entirely, the control holds and the finding fails.

*Disproof:* The claim is false when the resolver enforces the authorization itself, because a resolver-level check runs regardless of what the selection set asks for - which is exactly why returning null with no error, rather than a value, is the observable that separates the two. It is also false if the field is exposed through a separate root mutation or query the low-privilege account is denied at the operation level, since a different root field is a different authorization surface and belongs to a different finding. And a null value that the schema marks nullable is not evidence of enforcement: re-test against the non-null variant or with a field whose resolver would have to raise an error to deny access, and treat a silent null as inconclusive rather than as a pass.

**Alias or batch amplification is proved only when one HTTP request produces N distinct observable side effects - N created rows, N outbound backend calls visible in the response, or N distinct resolver results each carrying a different server-generated value - rather than merely N aliases appearing in the query text.**

Build the amplification payload so that each alias is distinguishable in the output: query the same list field N times under names a1..aN with a distinct unique argument per alias, or POST a JSON array of N operations. Then count what came back rather than what you sent. The strong pass condition is N non-identical values in the response data that the server itself generated - per-alias createdAt timestamps, per-alias ids, or a server-returned field that differs between aliases - because only then do you know N resolvers ran. The stronger form still is a side-effect count: N mutation aliases that each insert a row, confirmed by a follow-up read of the table showing N new rows you can attribute to that single request. Record N, the response byte size, and the wall-clock time for N = 10, 100 and 1000. A response of N aliased keys whose values are all identical, or an errors array where the aliased field was rejected, is a fail and must be reported as such rather than as amplification.

*Disproof:* The claim is false whenever the response contains GraphQL errors for the aliased selections, because an errored field contributes no resolver work to the data path and the amplification did not occur. It is also false if the server's only defence was an input-size or alias-count limit that rejected the whole request - a rejected request executed nothing. And it is false if the N values you observed are byte-identical, which indicates field-level response caching or deduplication rather than N executions; re-test with per-alias unique arguments that force distinct cache keys before claiming amplification.

**A depth or complexity denial-of-service is proved when the same operation at increasing nesting depth is accepted and the server-side cost rises measurably with depth - response time, resolver count, or database queries per second on the backend - rather than by the existence of a deep query in a request body.**

Hold everything constant except depth. Establish a baseline: a depth-2 query, three repetitions, median server-reported or client-measured response time T0 and a backend query count from any access log or APM trace you are entitled to read. Then send depth-10, depth-20 and depth-50 versions of the same shape and record T10, T20, T50 plus the per-request backend query count. A finding needs both acceptance at every depth - no max-depth error, HTTP 200 with data - and cost that grows with depth in a way you can point at: median time at depth 50 several multiples of T0, or one client request fanning out to hundreds of backend queries. State the multiplier, not the adjective. Repeat against a second endpoint on the same deployment to show it is the schema's shape rather than one resolver. Report the exact query text, the depth count per branch, and the timing table; a screenshot of a slow response with no baseline is not reproducible and does not pass this test.

*Disproof:* The claim is false if the endpoint rejects the operation at the configured depth with a GraphQL error naming the depth or complexity limit, because then the demand control is present and working - and the fact that such a limit exists is a mitigation to record, not a defect. It is also false if the added depth only increases the size of a static response while the backend query count stays flat, which indicates the extra levels resolve from an already-materialised object rather than from new I/O. Finally it is false if the timing growth is attributable to the client, to a rate limiter that answered with a cached 429 body, or to a shared test account's own data volume rather than to attacker-controlled query shape; re-run with a fresh minimal object and an authenticated baseline before concluding.

**Introspection is only a finding when an unauthenticated request to the production endpoint returns a populated __schema or __type payload naming the server's own types and fields, and an empty or errored response from the same request fails the test.**

Send the schema introspection query as a bare POST to the endpoint with no Authorization header, no cookie and no Referer, and read the response body rather than the status code. The pass condition is a data object containing __schema.types with an array whose entries carry names from the application's own vocabulary - business object names, mutation names, field names that appear in no documentation - not merely the introspection system's own built-in scalars. Anything less is a fail: an errors array, a data object with __schema null, or a types array holding only the handful of scalars the spec requires to be present. The spec is why the payload is sensitive at all: schema introspection is reachable from the __schema and __type meta-fields on the root query type, which are implicit and always part of the type system, so a server cannot claim the fields do not exist. Record the count of types and the list of mutation names you recovered, then re-run the identical request from a second, unauthenticated client to confirm the exposure is not an artifact of a cached authorized response.

*Disproof:* The claim is false when the unauthenticated response contains no application type names, which is the expected outcome of a disabled-introspection deployment or a production-only allowlist. It is also false when the schema detail you recovered came from Did you mean suggestions or validation-error text rather than from a __schema or __type selection, since that is a materially smaller disclosure - the error path does not enumerate the type system. And a schema recovered from a public staging environment, a published SDL file, or a developer GraphiQL instance is evidence about that environment, not about production, so it does not satisfy this test unless the same response shape is reproducible against the production endpoint.

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
- **checkmarx.com** (writeup)
  - <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>
- **cwe.mitre.org** (writeup)
  - <https://cwe.mitre.org/data/definitions/1220.html>
  - <https://cwe.mitre.org/data/definitions/200.html>
  - <https://cwe.mitre.org/data/definitions/400.html>
  - <https://cwe.mitre.org/data/definitions/749.html>
  - <https://cwe.mitre.org/data/definitions/770.html>
- **graphql.org** (writeup)
  - <https://graphql.org/learn/authorization/>
  - <https://graphql.org/learn/global-object-identification/>
  - <https://graphql.org/learn/performance/>
  - <https://graphql.org/learn/queries/>
  - <https://graphql.org/learn/response/>
  - <https://graphql.org/learn/schema/>
  - <https://graphql.org/learn/security/>
- **neo4j.com** (writeup)
  - <https://neo4j.com/docs/graphql/current/security/authorization/>
- **owasp.org** (writeup)
  - <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>
- **portswigger.net** (taxonomy)
  - <https://portswigger.net/web-security/graphql>
- **relay.dev** (standard)
  - <https://relay.dev/graphql/objectidentification.htm>
- **securitylabs.datadoghq.com** (research)
  - <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/>
- **spec.graphql.org** (writeup)
  - <https://spec.graphql.org/September2025/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
