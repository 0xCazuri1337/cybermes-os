# Methodology — GraphQL-Specific Attack Surface

> Derived from 13 verified items. Regenerate with `python -m wks.methodgen --class graphql --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**A node(id:) or nodes(ids:) field on the root Query type means any object can be fetched by global ID without traversing its parent resolver.**

Check the Query type: cat schema.json | jq '.data.__schema.types[] | select(.name=="Query") | .fields[] | .name' | grep node. Relay-style global IDs are base64("Type:id"), so base64 -d on any ID captured from a UI response exposes the sequential numeric id to feed straight back into node(id: "VXNlcjox"). Presence of this field plus sequential ids is the setup for enumeration.

- *Disproof:* No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A GraphQL API with introspection enabled in production discloses the types and operations the endpoint supports, including operations reserved for high-privilege users, and an undocumented endpoint absent from the gateway route table discloses by existing at all.**

The technique has two halves that compound. First, introspection: as Checkmarx describes it, introspection is a handy development feature that, when enabled in production, discloses the types and operations that are supported by the API, including sometimes queries and mutations that are only available to high privilege users. This is not cosmetic because schema fields often carry the names of privileged operations even when the resolver later denies access, so introspection yields a complete target list even when every call fails. The cited precedent is real: CVE-2021-4191 disclosed how GitLab's API allowed a remote, unauthenticated attacker to recover usernames, names and sometimes email addresses, because the User object type was exposed without any sort of authentication. Second, shadow APIs, endpoints existing in code but never documented or registered with the gateway, so gateway and WAF have no rule for them. Checkmarx's account of the 2022 APAC telco breach has exactly that shape: attackers scraped customer PII via an unsecured API endpoint publicly available on the internet, and an API Gateway or WAF may not have stopped it because it was unaware the endpoint existed. The hunt is to run introspection everywhere then diff the schema against the gateway route table; the difference is the shadow set.

- *Disproof:* If introspection is disabled or restricted to authenticated administrators in production, or the deployment enforces field-level authorisation inside the resolver rather than at the gateway, then the schema reveals no operation the caller could not already reach by name.
- *Evidence:* high_confidence — [checkmarx.com](https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/); [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/)

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

**Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.**

Baseline: issue isValidDiscount 5 times sequentially and note where 429 starts. Then send one request with 100 aliased calls (or a 100-element JSON array) and show all 100 land with no 429, because the limiter counted a single HTTP request. Observable side effects such as created rows beat a bare valid:true in the proof.

- *Disproof:* The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.**

Inspect data versus errors per alias: 'Cannot query field ...' or 'Variable $c of type Int was provided invalid value' means zero resolver executions, so the amplification never ran. For resource exhaustion, retest on production; a hang on staging with a smaller dataset is not a production availability bug, and an infra-level timeout that still returns a response caps the impact.

- *Disproof:* Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
- *Evidence:* high_confidence — [api-security.owasp.org](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/graphql)

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
