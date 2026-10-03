# GraphQL-Specific Attack Surface

> surface: `api` · CWE: CWE-1004 · OWASP: API8:2023
> maturity: **mature** — 13 items, 13 supported, 5 FP rules, 1 chains

A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.

**Aliases:** graphql, graphql introspection, graphql batching, alias overload, graphql injection, deeply nested query dos

## Prerequisite

- **Unauthenticated introspection on the production GraphQL endpoint is the precondition that converts one endpoint into a full map of queries, mutations and private fields.**  
  `high_confidence` · score 0.869 · disproved by: The probe returns "Introspection is disabled" or an authorization error, and no type, query or mutation names appear in the response body.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- **An attackable GraphQL surface is a single path (usually /graphql) that accepts a POST body with a JSON {"query": ...} document and serves every operation type.**  
  `high_confidence` · score 0.8415 · disproved by: Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Signal

- **A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.**  
  `high_confidence` · score 0.869 · disproved by: Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- **A node(id:) or nodes(ids:) field on the root Query type means any object can be fetched by global ID without traversing its parent resolver.**  
  `high_confidence` · score 0.8415 · disproved by: No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Technique

- **A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.**  
  `high_confidence` · score 0.869 · disproved by: The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- **Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.**  
  `high_confidence` · score 0.8415 · disproved by: The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Validation

- **Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.**  
  `high_confidence` · score 0.869 · disproved by: The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- **Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.**  
  `high_confidence` · score 0.8575 · disproved by: The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>

## Fp Rule

- **Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.**  
  `high_confidence` · score 0.8575 · disproved by: Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
  sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- **Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.**  
  `high_confidence` · score 0.83 · disproved by: The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
  sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Impact

- **A resolver that interpolates a string argument into a downstream SQL or HTTP call turns a plain GraphQL query into injection with server-side privileges.**  
  `high_confidence` · score 0.8575 · disproved by: Quote or bind parameters handle the argument, the endpoint rejects metacharacters, and payloads produce ordinary empty result sets with no behavioural difference.
  sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/749.html>

## Bypass

- **Authorization applied only in the frontend selection set is bypassed by requesting the hidden field directly, because the resolver returns it regardless of who asked.**  
  `high_confidence` · score 0.8965 · disproved by: The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>

## Chain Link

- **Over-broad public fields plus sequential ids chained through aliases turn a read-only exposure into full account enumeration; introspection chained to input types points at mass assignment.**  
  `high_confidence` · score 0.8575 · disproved by: The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
  sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>

## False-positive rules

- **Hypothesis:** A deeply nested GraphQL query caused a denial of service
  - **Invalidated by:** The 502 came from a staging host with no rate limiting; the production instance returned 200 in under 300ms for the identical query
  - **Rule:** A DoS reproduced only on dev/staging is not a production finding; confirm the hostname is in scope and behaviour differs before reporting

- **Hypothesis:** Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.
  - **Invalidated by:** Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
  - **Rule:** Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.

- **Hypothesis:** Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
  - **Invalidated by:** The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
  - **Rule:** Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
