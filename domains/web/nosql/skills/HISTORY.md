# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 16 (supported 16), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 16 (supported 16), FP rules 2, chains 1, state mature

```diff
--- nosql@current
+++ nosql@new
@@ -85,4 +85,4 @@
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
 ---
-Full class document: `domains/web/nosql/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id nosql`
+Full class document: `domains/web/nosql/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id nosql`
```

## 2026-10-02 19:37 — 115 diff lines
- items: 27 (supported 17), FP rules 4, chains 1, state mature

```diff
--- nosql@current
+++ nosql@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 943 · OWASP A03:2021
-> evidence: 16 items, 16 supported, 2 FP rules, 1 chains
+> evidence: 27 items, 17 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 A document query is built from a parsed structure so type and operator semantics become attacker-controlled.
@@ -26,28 +26,28 @@
 
 ## Techniques (what to change)
 
-- When exploiting SQL Injections, joins and subqueries are often used to leak data from different tables.
+- When exploiting SQL Injections, joins and subqueries are often used to leak data from different tables. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When exploiting SQL Injections, joins and subqueries are often used to leak data from diff".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Exploitation of this vulnerability works like this: an attacker requests a password reset for a user using their email address, uses the oracle to leak the newly created token, and finally uses that token to change the user’s password.
+- Exploitation of this vulnerability works like this: an attacker requests a password reset for a user using their email address, uses the oracle to leak the newly created token, and finally uses that token to change the user’s password. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of this vulnerability works like this: an attacker requests a password reset ".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a user’s password reset token.
+- The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a user’s password reset token. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a u".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- To escape a VM context, the attacker has to get access to objects from the parent context.
+- To escape a VM context, the attacker has to get access to objects from the parent context. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "To escape a VM context, the attacker has to get access to objects from the parent context.".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- But it still allows for more flexibility when exploiting this injection.
+- But it still allows for more flexibility when exploiting this injection. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "But it still allows for more flexibility when exploiting this injection.".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- We outlined how NoSQL Injections can be exploited, and how they can lead to a complete takeover of a Rocket.Chat instance.
+- We outlined how NoSQL Injections can be exploited, and how they can lead to a complete takeover of a Rocket.Chat instance. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We outlined how NoSQL Injections can be exploited, and how they can lead to a complete tak".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- "abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields.
+- "abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat tha".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
-- These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages.
+- These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These can allow attackers to escalate their privileges, to execute arbitrary system comman".
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
 - Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.
@@ -57,20 +57,56 @@
   - **Disproof:** If {"token":{"$regex":"^A"}} and {"token":{"$regex":"^ZZZZ"}} produce byte-identical responses, and the same for every prefix tried, there is no observable difference to build an oracle from and the blind character-leak technique does not work against this endpoint.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
 
+## Tests
+
+- To decide this case, observe: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass. It is actually the endpoint's intended contract: a public listing API with no authorization boundary. The observation that
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection) states the full boundary.
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a val _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.a_rejected_operator_object_is_not_injection) states the full boundary.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an a _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.bypass.a_server_side_filter_is_not_a_defence_against_client_supplied_operators) states the full boundary.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+- To decide this case, observe: stripped result set into full exfiltration of an admin's fields. So response-side filtering is not a control either: it is not enough to simply restrict the projection, i.e. the data that is returned from the query, because blind or error-based NoSQL Injections can still be used to leak that data. Try $where, $expr and $function in turn; any that changes behaviour is a working
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.bypass.blocklist_bypass_via_top_level_where_operator) states the full boundary.
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
+- To decide this case, observe: than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before th
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.an_unauthorized_document_returned_because_the_query_matched_more_is_still_injection_only_if_the_operator_was_attacker_controlled) states the full boundary.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+- To decide this case, observe: Mechanism: The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference. How to apply it in t
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.validation.boolean_operator_probe_is_the_observation_that_distinguishes_injection_from_normal_filtering) states the full boundary.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+
 ## Validation bar (how to prove it)
 
+- The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference.
+  - **Disproof:** The claim is false when the endpoint legitimately accepts a structured filter and applies the same type coercion to every caller, so the operator-shaped value is treated as a literal and the result set difference comes from the intended filter semantics; in that case the difference is documented behaviour and needs a second probe (a negative operator such as $where or $regex with a measurable side effect) to show attacker control.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 - A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.
   - **Disproof:** If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
 
 ## False-positive rules (when to reject it)
 
+- A NoSQL injection finding requires the attacker-supplied operator object to reach the query and change which documents match; an application that coerces the request body to a typed or validated model, or that strips keys beginning with `$`, produces a 400 or an unchanged result set and is not vulnerable.
+  - **Disproof:** The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a value taken out of the same body — because the primary query can be fully validated while the derived one still honours the injected operator.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+- Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.
+  - **Disproof:** The rule is wrong when the widening traces to a server-side query construction that merges the whole request body into the filter — even without an explicit `$`-prefixed payload, a body that legitimately carries an `owner` or `role` field is attacker-controlled and drives the operator-equivalent behaviour, so the two findings collapse into one injection with a non-`$` payload.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 - Reject a nosql finding until it is distinguished from the adjacent behaviour this class also covers. "An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a..." and "A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A JSON request field documented as a string that returns a structurall" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 - A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.
   - **Disproof:** If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
+
+## Evidence requirements
+
+- Reaching `$where` means a JavaScript expression is evaluated server-side, which is strictly stronger than reaching `$regex`, and MongoDB implements regex pattern matching with PCRE2, so a successful pattern probe is evidence of a ReDoS-capable sink rather than of arbitrary server-side code execution.
+  - **Disproof:** The claim is false on a deployment that disables `$where` (server-side JS execution is off by default in several managed configurations) while leaving `$regex` enabled, in which case only the pattern-level injection is reachable and the two must not be conflated; equally, a server that has disabled both operators shows neither.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-fields> · <https://www.mongodb.com/docs/manual/reference/operator/query/> · <https://www.mongodb.com/docs/manual/reference/operator/query/regex/>
 
 ## Impact framing
 
@@ -80,6 +116,9 @@
 
 ## Defence bypasses
 
+- Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it.
+  - **Disproof:** The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an allowlist of permitted fields, or the store applies the trusted clause separately from the user predicate — in which case the injected duplicate is dropped and the query is not widened.
+  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 - An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.
   - **Disproof:** If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
```

## 2026-10-03 01:46 — 144 diff lines
- items: 33 (supported 24), FP rules 6, chains 1, state mature

```diff
--- nosql@current
+++ nosql@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 943 · OWASP A03:2021
-> evidence: 27 items, 17 supported, 4 FP rules, 1 chains
+> evidence: 33 items, 24 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 A document query is built from a parsed structure so type and operator semantics become attacker-controlled.
@@ -28,54 +28,48 @@
 
 - When exploiting SQL Injections, joins and subqueries are often used to leak data from different tables. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When exploiting SQL Injections, joins and subqueries are often used to leak data from diff".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/>
 - Exploitation of this vulnerability works like this: an attacker requests a password reset for a user using their email address, uses the oracle to leak the newly created token, and finally uses that token to change the user’s password. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of this vulnerability works like this: an attacker requests a password reset ".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://cwe.mitre.org/data/definitions/943.html>
 - The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a user’s password reset token. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a u".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/>
 - To escape a VM context, the attacker has to get access to objects from the parent context. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "To escape a VM context, the attacker has to get access to objects from the parent context.".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/>
 - But it still allows for more flexibility when exploiting this injection. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "But it still allows for more flexibility when exploiting this injection.".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/>
 - We outlined how NoSQL Injections can be exploited, and how they can lead to a complete takeover of a Rocket.Chat instance. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We outlined how NoSQL Injections can be exploited, and how they can lead to a complete tak".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/>
 - "abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat tha".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://portswigger.net/web-security/nosql-injection>
 - These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These can allow attackers to escalate their privileges, to execute arbitrary system comman".
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://cwe.mitre.org/data/definitions/943.html>
 - Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.
   - **Disproof:** If {"password":{"$ne":1}} returns the same 401 and body as the wrong-password baseline while a correct password still returns 200, the credential is not compared through a query operator and the operator-injection auth bypass does not exist on that endpoint.
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/sast-vs-dast>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://firebase.google.com/docs/firestore/security/rules-query>
 - A $regex operator object in a lookup field turns the response into a boolean oracle, letting an attacker recover a secret token one character at a time by repeated prefix guesses against an unauthenticated endpoint.
   - **Disproof:** If {"token":{"$regex":"^A"}} and {"token":{"$regex":"^ZZZZ"}} produce byte-identical responses, and the same for every prefix tried, there is no observable difference to build an oracle from and the blind character-leak technique does not work against this endpoint.
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://firebase.google.com/docs/firestore/security/rules-query>
 
 ## Tests
 
-- To decide this case, observe: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass. It is actually the endpoint's intended contract: a public listing API with no authorization boundary. The observation that
+- To decide this case, observe: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection) states the full boundary.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a val _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.a_rejected_operator_object_is_not_injection) states the full boundary.
   - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an a _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.bypass.a_server_side_filter_is_not_a_defence_against_client_supplied_operators) states the full boundary.
   - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
-- To decide this case, observe: stripped result set into full exfiltration of an admin's fields. So response-side filtering is not a control either: it is not enough to simply restrict the projection, i.e. the data that is returned from the query, because blind or error-based NoSQL Injections can still be used to leak that data. Try $where, $expr and $function in turn; any that changes behaviour is a working
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.bypass.blocklist_bypass_via_top_level_where_operator) states the full boundary.
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
-- To decide this case, observe: than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before th
+- To decide this case, observe: Mechanism: Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.an_unauthorized_document_returned_because_the_query_matched_more_is_still_injection_only_if_the_operator_was_attacker_controlled) states the full boundary.
-  - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
-- To decide this case, observe: Mechanism: The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference. How to apply it in t
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.validation.boolean_operator_probe_is_the_observation_that_distinguishes_injection_from_normal_filtering) states the full boundary.
   - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 
 ## Validation bar (how to prove it)
@@ -83,30 +77,51 @@
 - The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference.
   - **Disproof:** The claim is false when the endpoint legitimately accepts a structured filter and applies the same type coercion to every caller, so the operator-shaped value is treated as a literal and the result set difference comes from the intended filter semantics; in that case the difference is documented behaviour and needs a second probe (a negative operator such as $where or $regex with a measurable side effect) to show attacker control.
   - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+- The canonical proof is a login query in which the username predicate is a real record and the password predicate is $ne with an empty value, because a successful login then demonstrates that the server-side filter's boolean logic was attacker-shaped rather than merely loose. _(unverified)_
+  - **Disproof:** It is not exploitable if the application performs the credential check outside the database - a fetch-then-compare in application code, or an LDAP/AD bind - so the filter never encodes the password condition. It also fails if the account has no password field at all, in which case $ne matches every user rather than confirming anything about this one, and the returned identity must be verified before the claim is made.
+  - Sources: <https://cwe.mitre.org/data/definitions/943.html> · <https://portswigger.net/web-security/nosql-injection>
 - A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.
   - **Disproof:** If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://portswigger.net/web-security/nosql-injection>
 
 ## False-positive rules (when to reject it)
 
+- String concatenation of user input into a JSON document handed to a MongoDB driver is a code smell but not, by itself, NoSQL injection, because the driver serialises the value as data and operator injection requires the attacker to control the structure of the parsed document.
+  - **Disproof:** It IS injection if the untrusted value becomes a key - a field name, an operator name, or a nested path segment - because a key cannot be escaped by value serialisation. It is also injection where a framework's parameter parser turns bracket syntax into nested objects before the application sees them, or where the application calls something like eval or JSON.parse on attacker input to build the filter. Show the attacker-controlled key or the parse step and the finding stands.
+  - Sources: <https://cwe.mitre.org/data/definitions/943.html> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 - A NoSQL injection finding requires the attacker-supplied operator object to reach the query and change which documents match; an application that coerces the request body to a typed or validated model, or that strips keys beginning with `$`, produces a 400 or an unchanged result set and is not vulnerable.
   - **Disproof:** The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a value taken out of the same body — because the primary query can be fully validated while the derived one still honours the injected operator.
   - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
+- Sending the operator payload as a plain string and getting a normal 'no results' response proves only that the value stayed a string, not that the endpoint is safe, because operator injection requires the parameter to arrive as a parsed object.
+  - **Disproof:** It IS a real negative result if the application type-checks the parameter before it reaches the store - OWASP lists type conversion with strict exception handling as a validation technique - so that the structured payload is coerced or rejected and the query runs with a scalar value. Prove it by showing the value arrives at the query builder as a string or is rejected with a type error; that makes the flat-string test sufficient and this fp_rule not applicable to that endpoint.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 - Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.
   - **Disproof:** The rule is wrong when the widening traces to a server-side query construction that merges the whole request body into the filter — even without an explicit `$`-prefixed payload, a body that legitimately carries an `owner` or `role` field is attacker-controlled and drives the operator-equivalent behaviour, so the two findings collapse into one injection with a non-`$` payload.
   - Sources: <https://firebase.google.com/docs/firestore/security/rules-query> · <https://www.mongodb.com/docs/manual/reference/operator/query/>
 - Reject a nosql finding until it is distinguished from the adjacent behaviour this class also covers. "An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a..." and "A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A JSON request field documented as a string that returns a structurall" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://portswigger.net/web-security/nosql-injection>
 - A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.
   - **Disproof:** If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
 
 ## Evidence requirements
 
+- A convincing observation for this class is: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection) states the full boundary.
+  - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
+- A convincing observation for this class is: An endpoint that returns a byte-identical response for matching and non-matching prefixes has no oracle.
... (truncated)
```
