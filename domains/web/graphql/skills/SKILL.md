---
name: graphql-hunting
description: Use when hunting GraphQL-Specific Attack Surface in a api target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# GraphQL-Specific Attack Surface — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `api` · CWE CWE-1004 · OWASP API8:2023
> evidence: 24 items, 18 supported, 6 FP rules, 1 chains
> maturity: **mature**

A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.

**Also called:** graphql, graphql introspection, graphql batching, alias overload, graphql injection, deeply nested query dos


## Prerequisites (do not start without these)

- An attackable GraphQL surface is a single path (usually /graphql) that accepts a POST body with a JSON {"query": ...} document and serves every operation type.  _(merged 1 duplicate row(s))_
  - **Disproof:** Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- Unauthenticated introspection on the production GraphQL endpoint is the precondition that converts one endpoint into a full map of queries, mutations and private fields.  _(merged 1 duplicate row(s))_
  - **Disproof:** The probe returns "Introspection is disabled" or an authorization error, and no type, query or mutation names appear in the response body.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Recon signals (where to look)

- A node(id:) or nodes(ids:) field on the root Query type exposes a standard mechanism for asking for an object by its global ID, so the object is reachable by ID rather than only through its parent field.  _(merged 1 duplicate row(s))_
  - **Disproof:** No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.
  - Sources: <https://graphql.org/learn/global-object-identification/> · <https://relay.dev/graphql/objectidentification.htm>
- A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.  _(merged 1 duplicate row(s))_
  - **Disproof:** Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Techniques (what to change)

- A GraphQL API with introspection enabled in production discloses the types and operations the endpoint supports, including operations reserved for high-privilege users, and an undocumented endpoint absent from the gateway route table discloses by existing at all.  _(merged 1 duplicate row(s))_
  - **Disproof:** If introspection is disabled or restricted to authenticated administrators in production, or the deployment enforces field-level authorisation inside the resolver rather than at the gateway, then the schema reveals no operation the caller could not already reach by name.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>
- A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.  _(merged 1 duplicate row(s))_
  - **Disproof:** The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.  _(merged 1 duplicate row(s))_
  - **Disproof:** The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Tests

- A depth or complexity denial-of-service is proved when the same operation at increasing nesting depth is accepted and the server-side cost rises measurably with depth - response time, resolver count, or database queries per second on the backend - rather than by the existence of a deep query in a request body.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false if the endpoint rejects the operation at the configured depth with a GraphQL error naming the depth or complexity limit, because then the demand control is present and working - and the fact that such a limit exists is a mitigation to record, not a defect. It is also false if the added depth only increases the size of a static response while the backend query count stays flat, which indicates the extra levels resolve from an already-materialised object rather than from new I/O. Finally it is false if the timing growth is attributable to the client, to a rate limiter that answered with a cached 429 body, or to a shared test account's own data volume rather than to attacker-controlled query shape; re-run with a fresh minimal object and an authenticated baseline before concluding.
  - Sources: <https://cwe.mitre.org/data/definitions/400.html> · <https://graphql.org/learn/performance/>
- Alias or batch amplification is proved only when one HTTP request produces N distinct observable side effects - N created rows, N outbound backend calls visible in the response, or N distinct resolver results each carrying a different server-generated value - rather than merely N aliases appearing in the query text.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false whenever the response contains GraphQL errors for the aliased selections, because an errored field contributes no resolver work to the data path and the amplification did not occur. It is also false if the server's only defence was an input-size or alias-count limit that rejected the whole request - a rejected request executed nothing. And it is false if the N values you observed are byte-identical, which indicates field-level response caching or deduplication rather than N executions; re-test with per-alias unique arguments that force distinct cache keys before claiming amplification.
  - Sources: <https://cwe.mitre.org/data/definitions/770.html> · <https://graphql.org/learn/performance/> · <https://graphql.org/learn/queries/>
- Authorization applied only where the frontend happens to select the field is bypassed when the same field, requested directly in a hand-built operation with no frontend involvement, returns the value the UI suppresses - a populated object rather than null or an error.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false when the resolver enforces the authorization itself, because a resolver-level check runs regardless of what the selection set asks for - which is exactly why returning null with no error, rather than a value, is the observable that separates the two. It is also false if the field is exposed through a separate root mutation or query the low-privilege account is denied at the operation level, since a different root field is a different authorization surface and belongs to a different finding. And a null value that the schema marks nullable is not evidence of enforcement: re-test against the non-null variant or with a field whose resolver would have to raise an error to deny access, and treat a silent null as inconclusive rather than as a pass.
  - Sources: <https://cwe.mitre.org/data/definitions/1220.html> · <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/> · <https://spec.graphql.org/September2025/>
- Introspection is only a finding when an unauthenticated request to the production endpoint returns a populated __schema or __type payload naming the server's own types and fields, and an empty or errored response from the same request fails the test.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the unauthenticated response contains no application type names, which is the expected outcome of a disabled-introspection deployment or a production-only allowlist. It is also false when the schema detail you recovered came from Did you mean suggestions or validation-error text rather than from a __schema or __type selection, since that is a materially smaller disclosure - the error path does not enumerate the type system. And a schema recovered from a public staging environment, a published SDL file, or a developer GraphiQL instance is evidence about that environment, not about production, so it does not satisfy this test unless the same response shape is reproducible against the production endpoint.
  - Sources: <https://cwe.mitre.org/data/definitions/200.html> · <https://graphql.org/learn/schema/> · <https://spec.graphql.org/September2025/>

## Validation bar (how to prove it)

- A resource-exhaustion finding in GraphQL needs evidence of backend cost; depth limiting is not the only control, because a shallow operation with many aliases can amplify load in a single HTTP request.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim does not hold when the server enforces a document allowlist or trusted documents, because an operation the attacker cannot author cannot carry a hundred aliases or a deep list nest, and the amplification is structurally unavailable. It also fails where the API enforces field-level pagination with a server-side maximum page size, because the aliased-query cost is then bounded per alias regardless of how many aliases appear. And a finding needs a measured delta - a 200 response to a large document proves only that the document was accepted, not that it cost anything, so a purely qualitative large-query report is not the evidence this rule asks for.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://graphql.org/learn/security/>
- Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>

## False-positive rules (when to reject it)

- A GraphQL response containing both data and errors is a partial success, not a rejection, so a field that returned data alongside a sibling field's error has executed and its authorization decision must be evaluated on that data.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false when the error is a request error rather than a field error, because those abort execution before the field resolvers run and no data key is produced - the finding then rests on the data being absent, not on the errors array being present. It also fails where a Non-Null field bubbles the null upward and erases the whole data key, which is the correct deny and must not be reported as partial success. And a response that omits the data key entirely while returning errors is a rejection under either reading, so the rule is only about reading partial responses properly.
  - Sources: <https://graphql.org/learn/response/> · <https://neo4j.com/docs/graphql/current/security/authorization/>
- Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.  _(merged 1 duplicate row(s))_
  - **Disproof:** Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- An API that refuses __schema introspection is not thereby protected, and a report that closes on 'introspection is disabled' is reporting the absence of one discovery channel, not the presence of authorization.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false as a statement about a given deployment when the operation surface is genuinely closed to untrusted clients by a control outside GraphQL - an mTLS or sender-constrained client credential, a client-certificate-gated gateway, or a document allowlist that only accepts operations the server itself issued. In that architecture obscurity is a genuine layer rather than the only layer, and an unauthenticated tester genuinely cannot discover the schema. It is also false as a claim that introspection-disabled APIs are always reachable - some servers reject unknown fields entirely with a request error and no partial data, which raises the bar considerably even though it is not a formal control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://graphql.org/learn/security/>
- Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.  _(merged 1 duplicate row(s))_
  - **Disproof:** The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Evidence requirements

- A convincing observation for this class is: Observable side effects such as created rows beat a bare valid:true in the proof.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (graphql.validation.rate_limit_bypass_proof) states the full boundary.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- A convincing observation for this class is: The field discipline is to read the data object, not the status code or the errors array.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (graphql.fp_rule.an_error_in_the_errors_key_is_not_a_rejected_query) states the full boundary.
  - Sources: <https://graphql.org/learn/response/> · <https://neo4j.com/docs/graphql/current/security/authorization/>

## Impact framing

- A resolver that interpolates a string argument into a downstream SQL or HTTP call turns a plain GraphQL query into injection with server-side privileges.  _(merged 1 duplicate row(s))_
  - **Disproof:** Quote or bind parameters handle the argument, the endpoint rejects metacharacters, and payloads produce ordinary empty result sets with no behavioural difference.
  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/749.html>

## Defence bypasses

- An authorization rule declared with an explicit operations list applies only to those operations, so a filter written for READ leaves UPDATE, DELETE and AGGREGATE unguarded on the same type.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the rule has no operations argument, since the library then treats the configuration as if the full list of operations had been provided and every operation is filtered. It is also false where validation rules rather than filter rules are in force on the type, because validation throws an error instead of silently narrowing, so the same scoping mistake produces a loud denial on the unlisted operations rather than a silent data exposure. And a type whose write paths are gated by a separate directive, a resolver-level check, or a database policy is not exposed by the filter's operations list, because the filter was never the only gate.
  - Sources: <https://graphql.org/learn/authorization/> · <https://neo4j.com/docs/graphql/current/security/authorization/>
- Authorization applied only in the frontend selection set is bypassed by requesting the hidden field directly, because the resolver returns it regardless of who asked.  _(merged 1 duplicate row(s))_
  - **Disproof:** The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Chaining opportunities

- Over-broad public fields plus sequential ids chained through aliases turn a read-only exposure into full account enumeration; introspection chained to input types points at mass assignment.  _(merged 1 duplicate row(s))_
  - **Disproof:** The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>

## Rejected before you report

- **A deeply nested GraphQL query caused a denial of service**
  - Killed by: The 502 came from a staging host with no rate limiting; the production instance returned 200 in under 300ms for the identical query
  - Rule: A DoS reproduced only on dev/staging is not a production finding; confirm the hostname is in scope and behaviour differs before reporting
- **Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.**
  - Killed by: Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
  - Rule: Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.
- **Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.**
  - Killed by: The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
  - Rule: Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.


## Hunt procedure

1. Run introspection, then batch many aliases in ONE request and look for a rate-limit or cost check that is applied per request rather than per field.
2. Test authorization on __typename-adjacent fields and on mutations, and check whether a depth limit exists at all.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/graphql/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id graphql`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
