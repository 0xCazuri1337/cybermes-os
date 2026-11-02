# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-01 22:49 — 1 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
(initial generation, 2026-10-01)
```

## 2026-10-01 22:49 — 17 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
--- graphql@current
+++ graphql@new
@@ -9,13 +9,9 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `api` · CWE CWE-1004 · OWASP API8:2023
+> surface `api` · CWE — · OWASP —
 > evidence: 12 items, 12 supported, 0 FP rules, 0 chains
 > maturity: **researching** — missing: methodology, fp_rules, chain, skill
-
-A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.
-
-**Also called:** graphql, graphql introspection, graphql batching, alias overload, graphql injection, deeply nested query dos
 
 
 ## Prerequisites (do not start without these)
```

## 2026-10-01 22:50 — 30 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
--- graphql@current
+++ graphql@new
@@ -31,21 +31,21 @@
 
 ## Techniques (what to change)
 
+- Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.
+  - **Disproof:** The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 - A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.
   - **Disproof:** The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
-- Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.
-  - **Disproof:** The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
   - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## Validation bar (how to prove it)
 
+- Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.
+  - **Disproof:** The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
 - Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.
   - **Disproof:** The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.
   - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
-- Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.
-  - **Disproof:** The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-01 22:55 — 87 diff lines
- items: 12 (supported 12), FP rules 0, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- graphql@current
+++ graphql@new
@@ -9,52 +9,56 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `api` · CWE — · OWASP —
-> evidence: 12 items, 12 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, fp_rules, chain, skill
+> surface `api` · CWE CWE-1004 · OWASP API8:2023
+> evidence: 12 items, 12 supported, 0 FP rules, 1 chains
+> maturity: **researching** — missing: methodology, fp_rules
+
+A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.
+
+**Also called:** graphql, graphql introspection, graphql batching, alias overload, graphql injection, deeply nested query dos
 
 
 ## Prerequisites (do not start without these)
 
 - Unauthenticated introspection on the production GraphQL endpoint is the precondition that converts one endpoint into a full map of queries, mutations and private fields.
   - **Disproof:** The probe returns "Introspection is disabled" or an authorization error, and no type, query or mutation names appear in the response body.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 - An attackable GraphQL surface is a single path (usually /graphql) that accepts a POST body with a JSON {"query": ...} document and serves every operation type.
   - **Disproof:** Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ## Recon signals (where to look)
 
 - A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.
   - **Disproof:** Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ## Techniques (what to change)
 
 - Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.
   - **Disproof:** The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 - A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.
   - **Disproof:** The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ## Validation bar (how to prove it)
 
 - Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.
   - **Disproof:** The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 - Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.
   - **Disproof:** The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ## False-positive rules (when to reject it)
 
 - Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.
   - **Disproof:** Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
-  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 - Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
   - **Disproof:** The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
-  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ## Impact framing
 
@@ -66,13 +70,13 @@
 
 - Authorization applied only in the frontend selection set is bypassed by requesting the hidden field directly, because the resolver returns it regardless of who asked.
   - **Disproof:** The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ## Chaining opportunities
 
 - Over-broad public fields plus sequential ids chained through aliases turn a read-only exposure into full account enumeration; introspection chained to input types points at mass assignment.
   - **Disproof:** The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
 ---
 Full class document: `classes/graphql.md` · retrieve more with `python -m wks.cli search "<query>" --class-id graphql`
```

## 2026-10-01 22:58 — 23 diff lines
- items: 12 (supported 12), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- graphql@current
+++ graphql@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-1004 · OWASP API8:2023
-> evidence: 12 items, 12 supported, 0 FP rules, 1 chains
+> evidence: 12 items, 12 supported, 1 FP rules, 1 chains
 > maturity: **researching** — missing: methodology, fp_rules
 
 A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.
@@ -78,5 +78,11 @@
   - **Disproof:** The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
 
+## Rejected before you report
+
+- **A deeply nested GraphQL query caused a denial of service**
+  - Killed by: The 502 came from a staging host with no rate limiting; the production instance returned 200 in under 300ms for the identical query
+  - Rule: A DoS reproduced only on dev/staging is not a production finding; confirm the hostname is in scope and behaviour differs before reporting
+
 ---
 Full class document: `classes/graphql.md` · retrieve more with `python -m wks.cli search "<query>" --class-id graphql`
```

## 2026-10-01 23:20 — 83 diff lines
- items: 13 (supported 13), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- graphql@current
+++ graphql@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-1004 · OWASP API8:2023
-> evidence: 12 items, 12 supported, 1 FP rules, 1 chains
+> evidence: 13 items, 13 supported, 1 FP rules, 1 chains
 > maturity: **researching** — missing: methodology, fp_rules
 
 A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.
@@ -22,43 +22,46 @@
 
 - Unauthenticated introspection on the production GraphQL endpoint is the precondition that converts one endpoint into a full map of queries, mutations and private fields.
   - **Disproof:** The probe returns "Introspection is disabled" or an authorization error, and no type, query or mutation names appear in the response body.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 - An attackable GraphQL surface is a single path (usually /graphql) that accepts a POST body with a JSON {"query": ...} document and serves every operation type.
   - **Disproof:** Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## Recon signals (where to look)
 
+- A node(id:) or nodes(ids:) field on the root Query type means any object can be fetched by global ID without traversing its parent resolver.
+  - **Disproof:** No node, nodes or __Node interface appears in the schema or in response errors, so objects are only reachable through parent resolvers with their own authorization.
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 - A response carrying {"data":{"__typename":"query"}}, or a populated __schema/__type block, confirms a live GraphQL root type rather than a lookalike REST route.
   - **Disproof:** Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## Techniques (what to change)
 
 - Aliasing one field N times, or posting a JSON array of N operations, multiplies resolver executions past per-request rate limits because limiters count HTTP requests, not operations.
   - **Disproof:** The single amplified request returns a validation error, a 429, or a data object with fewer entries than aliases sent, so no extra resolver work occurred.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 - A deeply nested query or a huge pagination argument runs unbounded resolver work when no depth or amount limit is configured, exhausting DB connections and CPU.
   - **Disproof:** The server rejects the document with a complexity/depth validation error before executing, or returns within baseline latency with a bounded result set.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## Validation bar (how to prove it)
 
 - Two accounts with different authorization scopes where A's query returns B's object data proves the resolver performs no object-level authorization.
   - **Disproof:** The cross-account query returns null, an empty object, or a 403/unauthorized GraphQL error identical to the response for a nonexistent id.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
 - Proving rate-limit bypass requires observing N real side effects from one HTTP request after the same operation standalone was throttled at k attempts.
   - **Disproof:** The batched request returns 429, is truncated by an operation limit, or produces side effects only as many times as standalone requests were sent.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
 - Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.
   - **Disproof:** Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
-  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 - Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
   - **Disproof:** The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
-  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## Impact framing
 
@@ -70,13 +73,13 @@
 
 - Authorization applied only in the frontend selection set is bypassed by requesting the hidden field directly, because the resolver returns it regardless of who asked.
   - **Disproof:** The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
 ## Chaining opportunities
 
 - Over-broad public fields plus sequential ids chained through aliases turn a read-only exposure into full account enumeration; introspection chained to input types points at mass assignment.
   - **Disproof:** The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html> · <https://portswigger.net/web-security/graphql>
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
 
 ## Rejected before you report
 
```

## 2026-10-01 23:46 — 11 diff lines
- items: 13 (supported 13), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- graphql@current
+++ graphql@new
@@ -11,7 +11,7 @@
 
 > surface `api` · CWE CWE-1004 · OWASP API8:2023
 > evidence: 13 items, 13 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, fp_rules
+> maturity: **researching** — missing: fp_rules
 
 A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.
 
```

## 2026-10-02 01:36 — 11 diff lines
- items: 13 (supported 13), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- graphql@current
+++ graphql@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-1004 · OWASP API8:2023
 > evidence: 13 items, 13 supported, 1 FP rules, 1 chains
```

## 2026-10-02 10:30 — 35 diff lines
- items: 13 (supported 12), FP rules 5, chains 1, state mature

```diff
--- graphql@current
+++ graphql@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-1004 · OWASP API8:2023
-> evidence: 13 items, 13 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: fp_rules
+> evidence: 13 items, 12 supported, 5 FP rules, 1 chains
+> maturity: **mature**
 
 A single flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route.
 
@@ -65,7 +65,7 @@
 
 ## Impact framing
 
-- A resolver that interpolates a string argument into a downstream SQL or HTTP call turns a plain GraphQL query into injection with server-side privileges.
+- A resolver that interpolates a string argument into a downstream SQL or HTTP call turns a plain GraphQL query into injection with server-side privileges. _(unverified)_
   - **Disproof:** Quote or bind parameters handle the argument, the endpoint rejects metacharacters, and payloads produce ordinary empty result sets with no behavioural difference.
   - Sources: <https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/> · <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
 
@@ -86,6 +86,12 @@
 - **A deeply nested GraphQL query caused a denial of service**
   - Killed by: The 502 came from a staging host with no rate limiting; the production instance returned 200 in under 300ms for the identical query
   - Rule: A DoS reproduced only on dev/staging is not a production finding; confirm the hostname is in scope and behaviour differs before reporting
+- **Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.**
+  - Killed by: Each alias and each array element returns its own populated data entry or side effect, and the same nested query measurably degrades the production instance.
+  - Rule: Alias or batch "success" is a false positive when the response body is GraphQL errors, and DoS impact is a false positive when it only reproduces on dev or staging.
+- **Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.**
+  - Killed by: The __schema query returns the full types, fields, and descriptions arrays, so the disclosure is real introspection rather than suggestion text.
+  - Rule: Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
 
 ---
 Full class document: `classes/graphql.md` · retrieve more with `python -m wks.cli search "<query>" --class-id graphql`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 13 (supported 12), FP rules 5, chains 1, state mature

```diff
--- graphql@current
+++ graphql@new
@@ -94,4 +94,4 @@
   - Rule: Schema detail recovered only from "Did you mean" suggestions or validation errors is a materially smaller finding than live introspection and must be reported separately.
 
 ---
-Full class document: `classes/graphql.md` · retrieve more with `python -m wks.cli search "<query>" --class-id graphql`
+Full class document: `skills/Web/graphql/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id graphql`
```
