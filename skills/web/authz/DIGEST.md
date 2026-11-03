<!-- GENERATED from db/wks.db — do not edit -->
# Missing Function-Level Authorization

> surface: `api` · CWE: CWE-862 · OWASP: API5:2023
> maturity: **mature** — 21 items, 13 supported, 2 FP rules, 1 chains

An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**Aliases:** missing function level authorization, bfla, admin endpoint exposure, unauthorized access to administrative function

## Technique

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
- **An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“An attacker could modify sensitive data, either by writing the data directly to ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Product does not check the ACL of a page accessed using an "include" directive, ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>

## Test

- **A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.**  
  `high_confidence` · score 0.8815 · disproved by: If the same request replayed as a lower-privileged or unauthenticated identity is rejected or returns only the caller's own authorized data, the permission check is present and the access control claim fails.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md>

## Validation

- **A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.**  
  `high_confidence` · score 0.838 · disproved by: The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.
  sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>

## Fp Rule

- **A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.
  sources: <https://portswigger.net/web-security/access-control> · <https://graphql.org/learn/authorization/>
- **A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.**  
  `high_confidence` · score 0.8105 · disproved by: The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.
  sources: <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html> · <https://graphql.org/learn/authorization/>

## Impact

- **An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**  
  `high_confidence` · score 0.9015 · disproved by: If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
  sources: <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898> · <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>
