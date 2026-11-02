# Methodology — GraphQL-Specific Attack Surface

> Derived from 18 verified items. Regenerate with `python -m wks.methodgen --class graphql --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.

**References.** CWE-1004 · API8:2023

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Unauthenticated introspection on the production GraphQL endpoint is the precondition that converts one endpoint into a full map of queries, mutations and private fields.**

Probe {"query":"{__schema{queryType{name}}}"}. If names come back unauthenticated in production, immediately dump __schema.types with descriptions; internal and admin-only types routinely survive in schemas. Most implementations ship introspection enabled and unauthenticated, so treat a live prod introspection probe as the green light for schema-driven testing.

- *Disproof:* The probe returns "Introspection is disabled" or an authorization error, and no type, query or mutation names appear in the response body.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

**An attackable GraphQL surface is a single path (usually /graphql) that accepts a POST body with a JSON {"query": ...} document and serves every operation type.**

Hunt: POST {"query":"query{__typename}"} to /graphql, /api/graphql, /graphql/api, /graphql/graphql, /api, then /v1 variants. A hit returns {"data":{"__typename":"query"}}. Because one endpoint serves queries and mutations alike, mapping it once exposes the whole API surface, so no other recon is worth doing until this lands.

- *Disproof:* Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.**

Keep two recon primitives: query{__typename} to confirm the service, and {"query":"{__schema{queryType{name}}}"} plus {__type(name:"User"){fields{name}}} to confirm schema reachability. A non-GraphQL route typically answers 404, HTML, or a generic JSON error, which tells you the endpoint guess was wrong rather than the API being hardened.

- *Disproof:* Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

**A node(id:) or nodes(ids:) field on the root Query type exposes a standard mechanism for asking for an object by its global ID, so the object is reachable by ID rather than only through its parent field.**

Check the Query type: cat schema.json | jq '.data.__schema.types[] | select(.name=="Query") | .fields[] | .name' | grep node. Relay-style global IDs are base64("Type:id"), so base64 -d on any ID captured from a UI response exposes the sequential numeric id to feed straight back into node(id: "VXNlcjox"). Presence of this field plus sequential ids is the setup for enumeration.

- *Disproof:* No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.
- *Evidence:* high_confidence — [graphql.org](https://graphql.org/learn/global-object-identification/); [relay.dev](https://relay.dev/graphql/objectidentification.htm)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A GraphQL API with introspection enabled in production discloses the types and operations the endpoint supports, including operations reserved for high-privilege users, and an undocumented endpoint absent from the gateway route table discloses by existing at all.**

The technique has two halves that compound. First, introspection: as Checkmarx describes it, introspection is a handy development feature that, when enabled in production, discloses the types and operations that are supported by the API, including sometimes queries and mutations that are only available to high privilege users. This is not cosmetic because schema fields often carry the names of privileged operations even when the resolver later denies access, so introspection yields a complete target list even when every call fails. The cited precedent is real: CVE-2021-4191 disclosed how GitLab's API allowed a remote, unauthenticated attacker to recover usernames, names and sometimes email addresses, because the User object type was exposed without any sort of authentication. Second, shadow APIs, endpoints existing in code but never documented or registered with the gateway, so gateway and WAF have no rule for them. Checkmarx's account of the 2022 APAC telco breach has exactly that shape: attackers scraped customer PII via an unsecured API endpoint publicly available on the internet, and an API Gateway or WAF may not have stopped it because it was unaware the endpoint existed. The hunt is to run introspection everywhere then diff the schema against the gateway route table; the difference is the shadow set.

- *Disproof:* If introspection is disabled or restricted to authenticated administrators in production, or the deployment enforces field-level authorisation inside the resolver rather than at the gateway, then the schema reveals no operation the caller could not already reach by name.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [checkmarx.com](https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/); [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/)

**A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.**

Build depth N: query evil { album(id:42) { songs { album { songs { album { id } } } } } }. Or request amount: { author(id:"abc") { posts(first: 99999999) { title } } }. GraphQL has no native depth or amount limiting - the missing limit is the finding, not merely the slow response.

- *Disproof:* The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

**Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.**

Send query isValidDiscount($c:Int){ a:isValidDiscount(code:$c){valid} b:isValidDiscount(code:$c){valid} ... } with a different $c per alias, or a body of [{"query":...},{"query":...}]. OWASP notes proxies and gateways relying on the raw number of requests will let this through, and that tooling sees one request rather than many.

- *Disproof:* The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A resource-exhaustion finding in GraphQL needs evidence of backend cost; depth limiting is not the only control, because a shallow operation with many aliases can amplify load in a single HTTP request.**

graphql.org separates three guards and the field test has to match the one you are actually probing. On depth: it is a good idea to limit the maximum depth of fields a single operation can have, and because nesting list fields can result in exponential increases to the amount of data returned it recommends a separate smaller limit on list nesting. On breadth: the guidance gives the alias case concretely - a query selecting friends1 through friends100 is shallow, yet the underlying data source still has to handle a large number of requests to resolve data for the aliased field - and it adds that there should be an upper limit on the total number of queries in a single batch. On rate limiting: depth, breadth and batch limiting prevent categories of malicious operation but do not provide a way to declare that a particular field is expensive. So the convincing evidence for exhaustion is a measured increase in backend work or latency for a small document, not a document that merely looks large.

- *Disproof:* The claim does not hold when the server enforces a document allowlist or trusted documents, because an operation the attacker cannot author cannot carry a hundred aliases or a deep list nest, and the amplification is structurally unavailable. It also fails where the API enforces field-level pagination with a server-side maximum page size, because the aliased-query cost is then bounded per alias regardless of how many aliases appear. And a finding needs a measured delta - a 200 response to a large document proves only that the document was accepted, not that it cost anything, so a purely qualitative large-query report is not the evidence this rule asks for.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [graphql.org](https://graphql.org/learn/security/); [portswigger.net](https://portswigger.net/web-security/graphql)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.**

Inspect data versus errors per alias: 'Cannot query field ...' or 'Variable $c of type Int was provided invalid value' means zero resolver executions, so the amplification never ran. For resource exhaustion, retest on production; a hang on staging with a smaller dataset is not a production availability bug, and an infra-level timeout that still returns a response caps the impact.

- *Disproof:* Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
- *Evidence:* high_confidence — [api-security.owasp.org](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

**An API that refuses __schema introspection is not thereby protected, and a report that closes on 'introspection is disabled' is reporting the absence of one discovery channel, not the presence of authorization.**

graphql.org's own position is that disabling introspection can be used as a form of security through obscurity but will not be sufficient to entirely obscure a GraphQL API by itself, and that it may be used as part of a broader strategy to limit discoverability rather than as the control. The field consequence is that a hunter cannot use 'introspection is off' to justify skipping the endpoint: the schema is still obtainable through field-error-driven inference, through the client's own bundles and source, through any documented example operation, and through simply knowing the operation names. Note the corollary that protects honest reports - graphql.org also says APIs serving only first-party clients may legitimately forbid introspection in non-development environments, so the finding is not 'introspection is enabled', it is 'a field returned data it should not have'. Introspection on a first-party-only API is a hardening observation at most.

- *Disproof:* The claim is false as a statement about a given deployment when the operation surface is genuinely closed to untrusted clients by a control outside GraphQL - an mTLS or sender-constrained client credential, a client-certificate-gated gateway, or a document allowlist that only accepts operations the server itself issued. In that architecture obscurity is a genuine layer rather than the only layer, and an unauthenticated tester genuinely cannot discover the schema. It is also false as a claim that introspection-disabled APIs are always reachable - some servers reject unknown fields entirely with a request error and no partial data, which raises the bar considerably even though it is not a formal control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [graphql.org](https://graphql.org/learn/security/)

**Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.**

If {"query":"{__schema{types{name}}}"} returns introspection-disabled but a typo like { userInf { id } } answers 'Did you mean userInfo?', you are hitting the suggestions feature, not introspection. Clairvoyance automates recovery this way. Downgrade the report: partial name disclosure, no schema graph, no private field dump.

- *Disproof:* The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
- *Evidence:* high_confidence — [api-security.owasp.org](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Authorization applied only in the frontend selection set is bypassed by requesting the hidden field directly, because the resolver returns it regardless of who asked.**

Diff what the UI sends (user { id name }) against your request (user { id name email role }): same response minus the hidden fields proves the UI is filtering. Aliasing that field under a new name, and replaying an allow-listed persisted-query hash over GET ?query=... or GET ?extensions=..., reaches the same resolver through a path the client never uses.

- *Disproof:* The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

**An authorization rule declared with an explicit operations list applies only to those operations, so a filter written for READ leaves UPDATE, DELETE and AGGREGATE unguarded on the same type.**

Declarative authorization in GraphQL tends to look like a schema-level control, which invites the assumption that annotating a type protects it. The mechanism is more granular than that: rules can be scoped to specific operations - READ, AGGREGATE, UPDATE, DELETE, CREATE, CREATE_RELATIONSHIP, DELETE_RELATIONSHIP - and a rule carrying an operations list is enforced only for those. That produces a specific and easily missed finding: a type filtered for reads still accepts an update that returns the row it should not have touched. The converse trap is that omitting the operations argument means the full list applies, so a rule without the list is safe and a rule with a partial list is not - the difference is one clause. Neo4j's documentation of both behaviours makes this a concrete check: when hunting, test each operation type against a resource you do not own rather than only the query you happened to construct during recon.

- *Disproof:* The claim is false when the rule has no operations argument, since the library then treats the configuration as if the full list of operations had been provided and every operation is filtered. It is also false where validation rules rather than filter rules are in force on the type, because validation throws an error instead of silently narrowing, so the same scoping mistake produces a loud denial on the unlisted operations rather than a silent data exposure. And a type whose write paths are gated by a separate directive, a resolver-level check, or a database policy is not exposed by the filter's operations list, because the filter was never the only gate.
- *Evidence:* high_confidence — [graphql.org](https://graphql.org/learn/authorization/); [neo4j.com](https://neo4j.com/docs/graphql/current/security/authorization/)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Over-broad public fields plus sequential ids chained through aliases turn a read-only exposure into full account enumeration; introspection chained to input types points at mass assignment.**

Once users/products expose email and sequential ids, batch the read: [{"query":"query{a:user(id:1){email}}"},{"query":"query{b:user(id:2){email}}"}] walks the whole base in one request. Introspection chains the other way: mutation input types and field descriptions reveal isAdmin/role/balance inputs that may bind straight to the model, which succeeds where guessing common sensitive fields is possible.

- *Disproof:* The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**A resolver that interpolates a string argument into a downstream SQL or HTTP call turns a plain GraphQL query into injection with server-side privileges.**

Hunt String-typed args (search, filter, slug) that reach raw SQL or an outbound fetch: { search(term: "' OR '1'='1") { id } }. OWASP notes user identifiers flow into HTTP requests, DB queries, and other calls, which is the injection opportunity. Impact escalates past schema disclosure to full DB read/write or internal service access.

- *Disproof:* Quote or bind parameters handle the argument, the endpoint rejects metacharacters, and payloads produce ordinary empty result sets with no behavioural difference.
- *Evidence:* high_confidence — [api-security.owasp.org](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/749.html)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
