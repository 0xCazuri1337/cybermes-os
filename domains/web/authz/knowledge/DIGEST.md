# Missing Function-Level Authorization

> surface: `api` · CWE: CWE-862 · OWASP: API5:2023
> maturity: **mature** — 21 items, 13 supported, 2 FP rules, 1 chains

An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**Aliases:** missing function level authorization, bfla, admin endpoint exposure, unauthorized access to administrative function

## Technique

- **ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.**  
  `under_review` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "ACL-based protection mechanism treats negative access rights as if they are positive, allo".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **System monitoring software allows users to bypass authorization by creating custom forms.**  
  `high_confidence` · score 0.7975 · disproved by: Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“System monitoring software allows users to bypass authorization by creating cust”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Terminal server does not check authorization for guest access.**  
  `high_confidence` · score 0.7975 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Terminal server does not check authorization for guest access.”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **The product does not perform an authorization check when an actor attempts to access a resource or perform an action.**  
  `high_confidence` · score 0.786 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The product does not perform an authorization check when an actor attempts to ac”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
- **An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.**  
  `high_confidence` · score 0.786 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“An attacker could read sensitive data, either by reading the data directly from ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
- **Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass a”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: product does not properly handle wildcards in an authorization policy lis”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this code is careful to avoid SQL Injection, the function does not confirm the user ".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“An attacker could modify sensitive data, either by writing the data directly to ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Product does not check the ACL of a page accessed using an "include" directive, ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>

## Test

- **To decide this case, observe: Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user.**  
  `under_review` · score 0.9205 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass) states the full boundary.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
- **A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.**  
  `high_confidence` · score 0.8815 · disproved by: If the same request replayed as a lower-privileged or unauthenticated identity is rejected or returns only the caller's own authorized data, the permission check is present and the access control claim fails.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md>

## Validation

- **A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.**  
  `high_confidence` · score 0.838 · disproved by: The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.
  sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>

## Fp Rule

- **A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.**  
  `under_review` · score 0.9565 · disproved by: If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
- **A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.**  
  `under_review` · score 0.9565 · disproved by: If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.
  sources: <https://portswigger.net/web-security/access-control> · <https://graphql.org/learn/authorization/>
- **A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.**  
  `high_confidence` · score 0.8105 · disproved by: The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.
  sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>

## Evidence

- **A convincing observation for this class is: The observable is the annotation plus a call site that never passes the proxy.**  
  `under_review` · score 0.783 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authz.bypass.a_secured_method_is_only_enforced_when_it_is_reached_through_the_proxy) states the full boundary.
  sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html>

## Impact

- **An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**  
  `high_confidence` · score 0.9015 · disproved by: If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
  sources: <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898> · <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>

## Bypass

- **Method-level authorization annotations are enforced by an interceptor around the bean, so an internal call path that reaches the annotated method without going through that bean - a self-invocation, a direct construction, a scheduled task, a deserialiser, or a second bean holding a reference - executes it completely unchecked.**  
  `under_review` · score 0.783 · disproved by: The claim is false when the method is final or private, since Spring AOP proxies cannot intercept those, and that cuts both ways - it means such a method is never checked regardless of the annotation, but also means the annotation there is inert by construction rather than by bypass. It is also false when method security is backed by AspectJ load-time or compile-time weaving rather than Spring AOP, since weaving instruments the bytecode and self-invocation is then enforced. And the bypass is not remotely reachable on its own: it needs an HTTP-reachable entry that takes the unchecked path, which is the separate condition the report must establish.
  sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html>

## Chain Link

- **Compromise of an internet-facing web application hands the next link whatever cloud scope that application's own identity carries, because application-held credentials and workload identity tokens are authorized independently of the user who reached the application.**  
  `under_review` · score 0.9175 · disproved by: If the application's identity is scoped to nothing outside its own resource, or the identity endpoint is unreachable from the compromised context, or the token is rejected for the target resource, then authentication alone did not grant broader authorization and the chain stops inside the application.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://learn.microsoft.com/en-us/aspnet/core/security/authorization> · <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
