# Methodology — Missing Function-Level Authorization

> Derived from 13 verified items. Regenerate with `python -m wks.methodgen --class authz --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**References.** CWE-862 · API5:2023

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**System monitoring software allows users to bypass authorization by creating custom forms.**

access to admin scripts, allowing authenticated users to reset administrative passwords. 
 
 
 
 
 
 
 
 CVE-2009-3597 
 
 
 
 
 Web application stores database file under the web root with insufficient access control ( CWE-219 ), allowing direct request. 
 
 
 
 
 
 
 
 CVE-2009-2282 
 
 
 
 
 Terminal server does not check authorization for guest access. 
 
 
 
 
 
 
 
 CVE-2008-5027 
 
 
 
 
 System monitoring software allows users to bypass authorization by creating custom forms. 
 
 
 
 
 
 
 
 CVE-2009-3781 
 
 
 
 
 Content management system does not check access permissions for private files, allowing others to view those files. 
 
 
 
 
 
 
 
 CVE-2008-6548 
 
 
 
 
 Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files. 
 
 
 
 
 
 
 
 CVE-2009-2960 
 
 
 
 
 Web application does not restrict ac

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“System monitoring software allows users to bypass authorization by creating cust”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

**Terminal server does not check authorization for guest access.**

sitive repository information 
 
 
 
 
 
 
 
 CVE-2009-3168 
 
 
 
 
 Web application does not restrict access to admin scripts, allowing authenticated users to reset administrative passwords. 
 
 
 
 
 
 
 
 CVE-2009-3597 
 
 
 
 
 Web application stores database file under the web root with insufficient access control ( CWE-219 ), allowing direct request. 
 
 
 
 
 
 
 
 CVE-2009-2282 
 
 
 
 
 Terminal server does not check authorization for guest access. 
 
 
 
 
 
 
 
 CVE-2008-5027 
 
 
 
 
 System monitoring software allows users to bypass authorization by creating custom forms. 
 
 
 
 
 
 
 
 CVE-2009-3781 
 
 
 
 
 Content management system does not check access permissions for private files, allowing others to view those files. 
 
 
 
 
 
 
 
 CVE-2008-6548 
 
 
 
 
 Product does not check the ACL of a page accessed using an "include" dire

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Terminal server does not check authorization for guest access.”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

**The product does not perform an authorization check when an actor attempts to access a resource or perform an action.**

ose it 
var modal = document.getElementById("customFilterModal"); 
window.onclick = function(event) { 
 if (event.target == document.getElementById("customFilterModal")) { 
 modal.style.display = "none"; 
 document.getElementById("customFilterLeftBox").innerHTML = ""; 
 document.getElementById("customFilterRightBox").innerHTML = ""; 
 } 
} 
 

 

 
 
 
 
 

 
 
 
 
 
 
 
 Description
 
 
 
 
 
 
 The product does not perform an authorization check when an actor attempts to access a resource or perform an action. 
 
 
 
 
 
 
 
 
 
 
 

 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 AuthZ
 
 
 "AuthZ" is typically used as an abbreviation of "authorization" within the web application security community. It is distinct from "AuthN" (or, sometimes, "AuthC") which is an abbreviation of "authentication." The use of "Auth" as an abbreviation is discouraged, since it could be used for either authentic

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The product does not perform an authorization check when an actor attempts to ac”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control)

**An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.**

equence is expected to be seen relative to the other
 consequences in the list. For example, there may be high likelihood that a weakness will be
 exploited to achieve a certain impact, but a low likelihood that it will be exploited to
 achieve a different impact. 
 
 
 Impact 
 Details 
 
 
 
 
 
 
 
 
 Read Application Data; Read Files or Directories 
 
 
 
 
 
 
 Scope: Confidentiality 
 
 
 
 An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. 
 
 
 
 
 
 
 
 
 Modify Application Data; Modify Files or Directories 
 
 
 
 
 
 
 Scope: Integrity 
 
 
 
 An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data. 
 
 
 
 
 
 
 
 
 Gain Privileges or Assume Identity; Bypass Protection Mechanism

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“An attacker could read sensitive data, either by reading the data directly from ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control)

**Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client.**

ngs. 
 
 
 
 
 
 
 
 CVE-2009-0034 
 
 
 
 
 Chain: product does not properly interpret a configuration option for a system group, allowing users to gain privileges. 
 
 
 
 
 
 
 
 CVE-2008-6123 
 
 
 
 
 Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect. 
 
 
 
 
 
 
 
 CVE-2008-7109 
 
 
 
 
 Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client. 
 
 
 
 
 
 
 
 CVE-2008-3424 
 
 
 
 
 Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. 
 
 
 
 
 
 
 
 CVE-2005-1036 
 
 
 
 
 Chain: Bypass of access restrictions due to improper authorization ( CWE-862 ) of a user results from an improperly initialized ( CWE-909 ) I/O permission bitmap 
 
 
 
 
 
 
 
 CVE-2008-4577 
 
 
 
 
 ACL-ba

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass a”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

**Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.**

ivileges. 
 
 
 
 
 
 
 
 CVE-2008-6123 
 
 
 
 
 Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect. 
 
 
 
 
 
 
 
 CVE-2008-7109 
 
 
 
 
 Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client. 
 
 
 
 
 
 
 
 CVE-2008-3424 
 
 
 
 
 Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. 
 
 
 
 
 
 
 
 CVE-2005-1036 
 
 
 
 
 Chain: Bypass of access restrictions due to improper authorization ( CWE-862 ) of a user results from an improperly initialized ( CWE-909 ) I/O permission bitmap 
 
 
 
 
 
 
 
 CVE-2008-4577 
 
 
 
 
 ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions. 
 
 
 
 
 
 
 
 CVE-2007-2925

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: product does not properly handle wildcards in an authorization policy lis”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

**An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data.**

pplication Data; Read Files or Directories 
 
 
 
 
 
 
 Scope: Confidentiality 
 
 
 
 An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. 
 
 
 
 
 
 
 
 
 Modify Application Data; Modify Files or Directories 
 
 
 
 
 
 
 Scope: Integrity 
 
 
 
 An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data. 
 
 
 
 
 
 
 
 
 Gain Privileges or Assume Identity; Bypass Protection Mechanism 
 
 
 
 
 
 
 Scope: Access Control 
 
 
 
 An attacker could gain privileges by modifying or reading critical data directly, or by accessing privileged functionality. 
 
 
 
 
 
 
 
 
 DoS: Crash, Exit, or Restart; DoS: Resource Consumption (CPU); DoS: Resource Consumption (Memory); DoS: Resource Consumption (Other

- *Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“An attacker could modify sensitive data, either by writing the data directly to ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

**Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.**

Terminal server does not check authorization for guest access. 
 
 
 
 
 
 
 
 CVE-2008-5027 
 
 
 
 
 System monitoring software allows users to bypass authorization by creating custom forms. 
 
 
 
 
 
 
 
 CVE-2009-3781 
 
 
 
 
 Content management system does not check access permissions for private files, allowing others to view those files. 
 
 
 
 
 
 
 
 CVE-2008-6548 
 
 
 
 
 Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files. 
 
 
 
 
 
 
 
 CVE-2009-2960 
 
 
 
 
 Web application does not restrict access to admin scripts, allowing authenticated users to modify passwords of other users. 
 
 
 
 
 
 
 
 CVE-2009-3230 
 
 
 
 
 Database server does not use appropriate privileges for certain sensitive operations. 
 
 
 
 
 
 
 
 CVE-2009-2213 
 
 
 
 
 Gateway uses default "Allow" configuration for its authorization sett

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Product does not check the ACL of a page accessed using an "include" directive, ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.**

Authentication and authorization are separate stages and most shortcut tests only exercise the first. A tester who removes the cookie, gets a 401, and concludes 'this endpoint is protected' has proved the presence of a session check and nothing else. The authorization question is whether account B, authenticated successfully, is refused the thing account A is allowed to do - and that requires two real accounts, because a single account cannot express a privilege difference. This is why the framework guidance separates the stages explicitly: GraphQL's own sequencing is that execution should begin after authentication middleware confirms the user's identity and passes that information to the GraphQL layer, and only after that do you determine whether the authenticated user is allowed to view the data provided by the specific fields included in the request. Field-level evidence must therefore name both identities and show the same request shape with the same operation, differing only in who is authenticated.

- *Disproof:* The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.
- *Evidence:* high_confidence — [docs.spring.io](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html); [graphql.org](https://graphql.org/learn/authorization/)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.**

This is the graphql.org lesson stated as a hunting rule, and it generalises past GraphQL to any API where the same predicate is repeated per handler. The argument graphql.org makes is that placing the ownership check inside the body resolver means the code has to be duplicated for each entry point into the service, and if the logic is not kept perfectly in sync, users see different data depending on which API they use. For the hunter that means a green check on one resolver is not evidence about the others: the primary query has the check, the batched form of the query does not, the nested selection that reaches the same type through a different path does not, and the REST endpoint that wraps the same repository does not. The productive move is to enumerate every path to the protected type - field, query, mutation, subscription, alias, fragment, batch array - and test each independently rather than accepting the schema as the control.

- *Disproof:* The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.
- *Evidence:* high_confidence — [graphql.org](https://graphql.org/learn/authorization/); [portswigger.net](https://portswigger.net/web-security/access-control)

**A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.**

URL-pattern authorization is evaluated as an ordered list where the first matching rule decides, which makes it a hunt for the earliest permissive entry rather than an assessment of the strictest one. A config that permits /api/** and then adds hasRole('ADMIN') for /api/admin/** looks, at a glance in a diff or a code snippet, like admin routes are locked down. They are not: nothing after the first match runs. Spring Security's own guidance frames the safe shape as the reverse - a catch-all deny at the end, described as a good strategy if you do not want to accidentally forget to update your authorization rules, which only works if the earlier entries are narrow. The field habit this should produce: read the rule list top to bottom and find the first entry whose pattern covers the endpoint under test. Confirming the endpoint sits behind a later rule is not evidence; the endpoint sits behind the earliest matching rule.

- *Disproof:* The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.
- *Evidence:* high_confidence — [docs.spring.io](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html); [graphql.org](https://graphql.org/learn/authorization/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Impact

_What is actually demonstrable, and what to stop claiming._

**An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**

Step: prove the write primitive by comparing a response that differs from a baseline read of the same record set before and after a single injected statement, then escalate only if the changed row is a role or ownership field. The attacker actually gains full administrative access to the application rather than a single record, because the authorization decision is read back out of the database the injection can write; from there application settings, stored data, and secrets reachable by the service are all in scope. Note that an unauthenticated write primitive needs no stolen credential to reach this ceiling, which is what makes the endpoint being unauthenticated by design the multiplier.

- *Disproof:* If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898); [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
