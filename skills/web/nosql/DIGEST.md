<!-- GENERATED from db/wks.db — do not edit -->
# NoSQL / Operator Injection

> surface: `web` · CWE: 943 · OWASP: A03:2021
> maturity: **mature** — 33 items, 18 supported, 2 FP rules, 1 chains

A document query is built from a parsed structure so type and operator semantics become attacker-controlled.

**Aliases:** nosql injection, mongo injection, operator injection

## Technique

- **Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.**  
  `high_confidence` · score 0.954 · disproved by: If {"password":{"$ne":1}} returns the same 401 and body as the wrong-password baseline while a correct password still returns 200, the credential is not compared through a query operator and the operator-injection auth bypass does not exist on that endpoint.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://firebase.google.com/docs/firestore/security/rules-query>
- **"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocke”) does not occur under a test that isolates that control.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://portswigger.net/web-security/nosql-injection>
- **These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These can allow attackers to escalate their privileges, to execute arbitrary sys”) does not occur under a test that isolates that control.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://cwe.mitre.org/data/definitions/943.html>

## Validation

- **A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.**  
  `high_confidence` · score 0.9265 · disproved by: If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://portswigger.net/web-security/nosql-injection>

## Fp Rule

- **Sending the operator payload as a plain string and getting a normal 'no results' response proves only that the value stayed a string, not that the endpoint is safe, because operator injection requires the parameter to arrive as a parsed object.**  
  `high_confidence` · score 0.893 · disproved by: It IS a real negative result if the application type-checks the parameter before it reaches the store - OWASP lists type conversion with strict exception handling as a validation technique - so that the structured payload is coerced or rejected and the query runs with a scalar value. Prove it by showing the value arrives at the query builder as a string or is rejected with a type error; that makes the flat-string test sufficient and this fp_rule not applicable to that endpoint.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
- **String concatenation of user input into a JSON document handed to a MongoDB driver is a code smell but not, by itself, NoSQL injection, because the driver serialises the value as data and operator injection requires the attacker to control the structure of the parsed document.**  
  `high_confidence` · score 0.783 · disproved by: It IS injection if the untrusted value becomes a key - a field name, an operator name, or a nested path segment - because a key cannot be escaped by value serialisation. It is also injection where a framework's parameter parser turns bracket syntax into nested objects before the application sees them, or where the application calls something like eval or JSON.parse on attacker input to build the filter. Show the attacker-controlled key or the parse step and the finding stands.
  sources: <https://cwe.mitre.org/data/definitions/943.html> · <https://www.mongodb.com/docs/manual/reference/operator/query/>

## Evidence

- **Reaching `$where` means a JavaScript expression is evaluated server-side, which is strictly stronger than reaching `$regex`, and MongoDB implements regex pattern matching with PCRE2, so a successful pattern probe is evidence of a ReDoS-capable sink rather than of arbitrary server-side code execution.**  
  `high_confidence` · score 0.8815 · disproved by: The claim is false on a deployment that disables `$where` (server-side JS execution is off by default in several managed configurations) while leaving `$regex` enabled, in which case only the pattern-level injection is reachable and the two must not be conflated; equally, a server that has disabled both operators shows neither.
  sources: <https://firebase.google.com/docs/firestore/security/rules-fields> · <https://www.mongodb.com/docs/manual/reference/operator/query/> · <https://www.mongodb.com/docs/manual/reference/operator/query/regex/>
- **Any claim that a NoSQL injection yields server-side JavaScript execution must first show the query used $where or mapReduce, because the ordinary comparison operators return data and never evaluate attacker-supplied code.**  
  `high_confidence` · score 0.783 · disproved by: The access-control claim survives regardless of $where - if $ne widened the result set, records were disclosed whether or not any code ran. And $where being available is not by itself reachable injection: it must be in the query the attacker can influence. Show the query text and the widened result set separately and label each for the impact it actually supports.
  sources: <https://portswigger.net/web-security/nosql-injection> · <https://www.mongodb.com/docs/manual/reference/operator/query/where/>

## Impact

- **A single blind NoSQL injection that leaks a password reset token escalates to full account takeover of an administrator, because the leaked token authorises a password reset and the admin session then exposes far more attack surface.**  
  `high_confidence` · score 0.9265 · disproved by: If the recovered token is rejected by the reset endpoint (invalid/expired), or the resulting session is denied every privileged route, then the leak does not convert into account takeover and the impact claim reduces to a single blind token disclosure.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
- **NoSQL injection impact extends beyond authentication bypass: it can yield unauthorized data disclosure, data modification, privilege escalation at the application layer, and in the worst case remote code execution on the database server, exposing the entire backend data store.**  
  `high_confidence` · score 0.799 · disproved by: If all inputs are type-validated to scalars and the query engine rejects operator keys, impact is limited to reflected content only; if the database has dropped JS execution capability, OS-level compromise is not achievable.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/943.html> · <https://github.com/cr0hn/vulnerable-node-mongo> · <https://owasp.org/Top10/A03_2021-Injection/> · <https://portswigger.net/web-security/nosql-injection>

## Bypass

- **An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.**  
  `high_confidence` · score 0.9265 · disproved by: If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- **Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it.**  
  `high_confidence` · score 0.838 · disproved by: The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an allowlist of permitted fields, or the store applies the trusted clause separately from the user predicate — in which case the injected duplicate is dropped and the query is not widened.
  sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
- **A filter that only ever compares one scalar against one submitted value is bypassable with array-valued and negated operators such as $nin and $ne, which change the comparison's shape rather than its content.**  
  `high_confidence` · score 0.8105 · disproved by: It is blocked if the application coerces the parameter to a scalar of declared type before building the filter, or allowlists the exact set of accepted operators for a queryable field, or uses a driver API that accepts only typed values. It also fails as a bypass if the store is not MongoDB or a compatible document database and does not implement the operator - check the actual backend before assuming operator semantics.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
- **Authentication can be bypassed in a NoSQL login by supplying a query operator that always matches (e.g., {"$ne": null} or {"$gt": ""}) in the password or credential field, so the query returns the target user's document and the application logs the attacker in without a valid password.**  
  `high_confidence` · score 0.799 · disproved by: If the application uses parameterized queries / a query builder that escapes or type-coerces input (e.g., passing input as a string value), $ne/$gt are never evaluated as operators and the bypass fails.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/943.html> · <https://github.com/cr0hn/vulnerable-node-mongo> · <https://portswigger.net/web-security/nosql-injection> · <https://www.mongodb.com/docs/manual/core/query-operators/>

## Chain Link

- **NoSQL operator injection in a search or filter endpoint, when combined with broken object-level authorization (BOLA/IDOR, CWE-639), allows an attacker to escalate a query from one user's view to a broader dataset, and eventually to full data exposure of the collection.**  
  `high_confidence` · score 0.8625 · disproved by: If the query is anchored to a fixed user ID (e.g., {"user_id": ObjectId(session_user)}) and input cannot alter that subfield, the operator injection cannot change the scoping; if the application enforces per-object ownership checks after the query, the BOLA step fails.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/943.html> · <https://github.com/cr0hn/vulnerable-node-mongo> · <https://owasp.org/Top10/A03_2021-Injection/> · <https://portswigger.net/web-security/nosql-injection>

## Vulnerability

- **NoSQL injection lets an attacker inject query operators (e.g., $ne, $gt, $regex, $where) into loosely typed inputs, bypassing authentication or extracting data from a NoSQL database.**  
  `high_confidence` · score 0.89 · disproved by: If all query inputs are type-validated and the application rejects non-string values where strings are expected, or if no query operators are accepted, injection is neutralized. A login attempt that fails even when sending operator objects disproves exploitation.
  sources: <https://cwe.mitre.org/data/definitions/943.html> · <https://portswigger.net/web-security/nosql-injection> · <https://www.invicti.com/blog/web-security/nosql-injection-cheat-sheet>

## Injection

- **NoSQL frameworks exposing aggregation stages ($function, $accumulator), map-reduce, or JS evaluation in the query layer allow injection of arbitrary JavaScript, leading to remote code execution on the database server rather than just query manipulation.**  
  `high_confidence` · score 0.89 · disproved by: If user input never reaches a JavaScript execution path (validation rejects non-literal input, or the framework only supports safe operators), code execution is not possible.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html> · <https://github.com/cr0hn/vulnerable-node-mongo> · <https://portswigger.net/web-security/nosql-injection> · <https://www.mongodb.com/docs/manual/core/query-operators/> · <https://www.mongodb.com/docs/manual/reference/operator/aggregation/function/>
- **User-supplied input is concatenated directly into a NoSQL query (e.g., MongoDB $and/$or selectors), allowing an attacker to inject query operators such as $gt, $ne, $regex, $where, or $expr and alter query logic beyond the application's intent.**  
  `high_confidence` · score 0.799 · disproved by: If the input is strictly validated to a primitive type (e.g., a string email or a numeric ID), operator keys like $gt are rejected; if the driver/ORM wraps user input in a BSON/literal and never merges it as a selector, injection is not possible.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/943.html> · <https://github.com/cr0hn/vulnerable-node-mongo> · <https://portswigger.net/web-security/nosql-injection> · <https://www.mongodb.com/docs/manual/core/query-operators/>
