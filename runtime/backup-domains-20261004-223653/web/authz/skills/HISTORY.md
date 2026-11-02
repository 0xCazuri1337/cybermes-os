# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 18 (supported 18), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 18 (supported 18), FP rules 2, chains 1, state mature

```diff
--- authz@current
+++ authz@new
@@ -85,4 +85,4 @@
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://learn.microsoft.com/en-us/aspnet/core/security/authorization> · <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
 
 ---
-Full class document: `domains/web/authz/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authz`
+Full class document: `domains/web/authz/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authz`
```

## 2026-10-02 19:37 — 87 diff lines
- items: 17 (supported 4), FP rules 2, chains 1, state mature

```diff
--- authz@current
+++ authz@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-862 · OWASP API5:2023
-> evidence: 18 items, 18 supported, 2 FP rules, 1 chains
+> evidence: 17 items, 4 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.
@@ -20,48 +20,48 @@
 
 ## Techniques (what to change)
 
-- The product does not perform an authorization check when an actor attempts to access a resource or perform an action.
+- The product does not perform an authorization check when an actor attempts to access a resource or perform an action. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
-- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.
+- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
-- While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While the program properly exits if authentication fails, it does not ensure that the mess".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client.
+- Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorizati".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- The product does not perform an authorization check when an actor attempts to access a resource or perform an action.
+- The product does not perform an authorization check when an actor attempts to access a resource or perform an action. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
-- ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.
+- ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "ACL-based protection mechanism treats negative access rights as if they are positive, allo".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- System monitoring software allows users to bypass authorization by creating custom forms.
+- System monitoring software allows users to bypass authorization by creating custom forms. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "System monitoring software allows users to bypass authorization by creating custom forms.".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.
+- Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly handle wildcards in an authorization policy list, allowin".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.
+- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
-- While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so.
+- While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this code is careful to avoid SQL Injection, the function does not confirm the user ".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data.
+- An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could modify sensitive data, either by writing the data directly to a data sto".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence ( CWE-783 ), allowing bypass of DNS-based access restrictions.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly check the result of a reverse DNS lookup because of opera".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Terminal server does not check authorization for guest access.
+- Terminal server does not check authorization for guest access. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Terminal server does not check authorization for guest access.".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.
+- Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Product does not check the ACL of a page accessed using an "include" directive, allowing a".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+
+## Tests
+
+- To decide this case, observe: page, while the authenticated call returns the same resource you could already read as that user. The finding survives only when the authenticated response contains object data the same user was never entitled to, or when the status flips because the endpoint skipped its ownership predicate entirely.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
 
 ## False-positive rules (when to reject it)
 
@@ -80,7 +80,7 @@
 
 ## Chaining opportunities
 
-- Compromise of an internet-facing web application hands the next link whatever cloud scope that application's own identity carries, because application-held credentials and workload identity tokens are authorized independently of the user who reached the application.
+- Compromise of an internet-facing web application hands the next link whatever cloud scope that application's own identity carries, because application-held credentials and workload identity tokens are authorized independently of the user who reached the application. _(unverified)_
   - **Disproof:** If the application's identity is scoped to nothing outside its own resource, or the identity endpoint is unreachable from the compromised context, or the token is rejected for the target resource, then authentication alone did not grant broader authorization and the chain stops inside the application.
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://learn.microsoft.com/en-us/aspnet/core/security/authorization> · <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
 
```

## 2026-10-03 01:46 — 61 diff lines
- items: 22 (supported 9), FP rules 4, chains 1, state mature

```diff
--- authz@current
+++ authz@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-862 · OWASP API5:2023
-> evidence: 17 items, 4 supported, 2 FP rules, 1 chains
+> evidence: 22 items, 9 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.
@@ -59,12 +59,24 @@
 
 ## Tests
 
-- To decide this case, observe: page, while the authenticated call returns the same resource you could already read as that user. The finding survives only when the authenticated response contains object data the same user was never entitled to, or when the status flips because the endpoint skipped its ownership predicate entirely.
+- To decide this case, observe: Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
 
+## Validation bar (how to prove it)
+
+- A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.
+  - **Disproof:** The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.
+  - Sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>
+
 ## False-positive rules (when to reject it)
 
+- A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.
+  - **Disproof:** The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.
+  - Sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>
+- A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.
+  - **Disproof:** The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://graphql.org/learn/authorization/>
 - A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.
   - **Disproof:** If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
@@ -72,11 +84,23 @@
   - **Disproof:** If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The observable is the annotation plus a call site that never passes the proxy.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authz.bypass.a_secured_method_is_only_enforced_when_it_is_reached_through_the_proxy) states the full boundary.
+  - Sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html>
+
 ## Impact framing
 
 - An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.
   - **Disproof:** If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
   - Sources: <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898> · <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>
+
+## Defence bypasses
+
+- Method-level authorization annotations are enforced by an interceptor around the bean, so an internal call path that reaches the annotated method without going through that bean - a self-invocation, a direct construction, a scheduled task, a deserialiser, or a second bean holding a reference - executes it completely unchecked.
+  - **Disproof:** The claim is false when the method is final or private, since Spring AOP proxies cannot intercept those, and that cuts both ways - it means such a method is never checked regardless of the annotation, but also means the annotation there is inert by construction rather than by bypass. It is also false when method security is backed by AspectJ load-time or compile-time weaving rather than Spring AOP, since weaving instruments the bytecode and self-invocation is then enforced. And the bypass is not remotely reachable on its own: it needs an HTTP-reachable entry that takes the unchecked path, which is the separate condition the report must establish.
+  - Sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html>
 
 ## Chaining opportunities
 
```

## 2026-10-03 02:41 — 21 diff lines
- items: 23 (supported 10), FP rules 4, chains 1, state mature

```diff
--- authz@current
+++ authz@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-862 · OWASP API5:2023
-> evidence: 22 items, 9 supported, 4 FP rules, 1 chains
+> evidence: 23 items, 10 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.
@@ -62,6 +62,9 @@
 - To decide this case, observe: Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
+- A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.
+  - **Disproof:** If the same request replayed as a lower-privileged or unauthenticated identity is rejected or returns only the caller's own authorized data, the permission check is present and the access control claim fails.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-04 00:43 — 152 diff lines
- items: 23 (supported 10), FP rules 4, chains 1, state mature

```diff
--- authz@current
+++ authz@new
@@ -20,96 +20,105 @@
 
 ## Techniques (what to change)
 
-- The product does not perform an authorization check when an actor attempts to access a resource or perform an action. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
-- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. _(unverified)_
+- ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "ACL-based protection mechanism treats negative access rights as if they are positive, allo".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could modify sensitive data, either by writing the data directly to a data sto".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
-- Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client. _(unverified)_
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
+- Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly handle wildcards in an authorization policy list, allowin".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorizati".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- The product does not perform an authorization check when an actor attempts to access a resource or perform an action. _(unverified)_
+- Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Product does not check the ACL of a page accessed using an "include" directive, allowing a".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- System monitoring software allows users to bypass authorization by creating custom forms.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "System monitoring software allows users to bypass authorization by creating custom forms.".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- Terminal server does not check authorization for guest access.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Terminal server does not check authorization for guest access.".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- The product does not perform an authorization check when an actor attempts to access a resource or perform an action.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
-- ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "ACL-based protection mechanism treats negative access rights as if they are positive, allo".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- System monitoring software allows users to bypass authorization by creating custom forms. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "System monitoring software allows users to bypass authorization by creating custom forms.".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly handle wildcards in an authorization policy list, allowin".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
-- While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so. _(unverified)_
+- While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this code is careful to avoid SQL Injection, the function does not confirm the user ".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could modify sensitive data, either by writing the data directly to a data sto".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Terminal server does not check authorization for guest access. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Terminal server does not check authorization for guest access.".
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
-- Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Product does not check the ACL of a page accessed using an "include" directive, allowing a".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
 
 ## Tests
 
-- To decide this case, observe: Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user.
+- A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the same request replayed as a lower-privileged or unauthenticated identity is rejected or returns only the caller's own authorized data, the permission check is present and the access control claim fails.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md>
+- To decide this case, observe: Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
-- A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.
-  - **Disproof:** If the same request replayed as a lower-privileged or unauthenticated identity is rejected or returns only the caller's own authorized data, the permission check is present and the access control claim fails.
-  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md>
 
 ## Validation bar (how to prove it)
 
-- A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.
+- A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.
   - Sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>
 
 ## False-positive rules (when to reject it)
 
-- A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.
+- A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.
   - Sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>
-- A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.
+- A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+- A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://graphql.org/learn/authorization/>
-- A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.
+- A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
-- A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.
-  - **Disproof:** If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
-  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable is the annotation plus a call site that never passes the proxy.
+- A convincing observation for this class is: The observable is the annotation plus a call site that never passes the proxy.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authz.bypass.a_secured_method_is_only_enforced_when_it_is_reached_through_the_proxy) states the full boundary.
   - Sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html>
 
 ## Impact framing
 
-- An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.
+- An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
   - Sources: <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898> · <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>
... (truncated)
```

## 2026-10-04 13:16 — 21 diff lines
- items: 24 (supported 11), FP rules 4, chains 1, state mature

```diff
--- authz@current
+++ authz@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-862 · OWASP API5:2023
-> evidence: 23 items, 10 supported, 4 FP rules, 1 chains
+> evidence: 24 items, 11 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.
@@ -38,6 +38,9 @@
 - Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Product does not check the ACL of a page accessed using an "include" directive, allowing a".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
+- Public writeup evidence for authz: self-registration onto a data platform.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://bobdahacker.com/blog/fifa-hack>
 - System monitoring software allows users to bypass authorization by creating custom forms.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "System monitoring software allows users to bypass authorization by creating custom forms.".
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
```
