# Missing Function-Level Authorization

## Definition

An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

- **CWE:** CWE-862
- **OWASP:** API5:2023
- **Surface:** api
- **Aliases:** ["missing function level authorization", "bfla", "admin endpoint exposure", "unauthorized access to administrative function"]

Canonical home for `authz`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **api**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable is the annotation plus a call site that never passes the proxy.**

Derived from authz.bypass.a_secured_method_is_only_enforced_when_it_is_reached_through_the_proxy, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authz.bypass.a_secured_method_is_only_enforced_when_it_is_reached_through_the_proxy) states the full boundary.

## Exploitation

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorizati".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".

**ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.**

lient. 
 
 
 
 
 
 
 
 CVE-2008-3424 
 
 
 
 
 Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. 
 
 
 
 
 
 
 
 CVE-2005-1036 
 
 
 
 
 Chain: Bypass of access restrictions due to improper authorization ( CWE-862 ) of a user results from an improperly initialized ( CWE-909 ) I/O permission bitmap 
 
 
 
 
 
 
 
 CVE-2008-4577 
 
 
 
 
 ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions. 
 
 
 
 
 
 
 
 CVE-2007-2925 
 
 
 
 
 Default ACL list for a DNS server does not set certain ACLs, allowing unauthorized DNS queries. 
 
 
 
 
 
 
 
 CVE-2006-6679 
 
 
 
 
 Product relies on the X-Forwarded-For HTTP header for authorization, allowing unintended access by spoofing the header. 
 
 
 
 
 
 
 
 CVE-2005-3623 
 
 
 
 
 OS kernel does not check for a certain privilege before setting

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "ACL-based protection mechanism treats negative access rights as if they are positive, allo".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "System monitoring software allows users to bypass authorization by creating custom forms.".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly handle wildcards in an authorization policy list, allowin".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".

**While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so.**

obalDbHandle) or die("Could not open Database".$dbName); 
 //Use a prepared statement to avoid CWE-89 
 $preparedStatement = $globalDbHandle->prepare('SELECT * FROM employees WHERE name = :name'); $preparedStatement->execute(array(':name' => $name)); return $preparedStatement->fetchAll(); } 
 /.../ 
 
 $employeeRecord = runEmployeeQuery('EmployeeDB',$_GET['EmployeeName']); 
 
 
 
 
 
 
 
 
 
 
 
 While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so. An attacker may be able to obtain sensitive employee information from the database. 
 
 
 
 
 
 
 Example 2 
 
 
 The following program could be part of a bulletin board system that allows users to send private messages to each other. This program intends to authenticate the user before deciding whether a private message should be displayed. Assume that LookupMessageObject() ensures that the $id

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this code is careful to avoid SQL Injection, the function does not confirm the user ".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could modify sensitive data, either by writing the data directly to a data sto".

**Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence ( CWE-783 ), allowing bypass of DNS-based access restrictions.**

header for authorization, allowing unintended access by spoofing the header. 
 
 
 
 
 
 
 
 CVE-2005-3623 
 
 
 
 
 OS kernel does not check for a certain privilege before setting ACLs for files. 
 
 
 
 
 
 
 
 CVE-2005-2801 
 
 
 
 
 Chain: file-system code performs an incorrect comparison ( CWE-697 ), preventing default ACLs from being properly applied. 
 
 
 
 
 
 
 
 CVE-2001-1155 
 
 
 
 
 Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence ( CWE-783 ), allowing bypass of DNS-based access restrictions. 
 
 
 
 
 
 
 
 CVE-2020-17533 
 
 
 
 
 Chain: unchecked return value ( CWE-252 ) of some functions for policy enforcement leads to authorization bypass ( CWE-862 ) 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Detection
 Me

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly check the result of a reverse DNS lookup because of opera".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Terminal server does not check authorization for guest access.".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Product does not check the ACL of a page accessed using an "include" directive, allowing a".

## Variations

**Method-level authorization annotations are enforced by an interceptor around the bean, so an internal call path that reaches the annotated method without going through that bean - a self-invocation, a direct construction, a scheduled task, a deserialiser, or a second bean holding a reference - executes it completely unchecked.**

The mechanism behind Spring's method security is that @EnableMethodSecurity publishes advisors which are woven into the set of advice that AuthorizationProxyFactory adds when proxying an object, and expressions using returnObject or filterObject sit behind the proxy so they have full access to the object. That 'behind the proxy' wording is the whole vulnerability class: the annotation is not a property of the code, it is a property of one call path. Spring's own idiom of annotating both a service method and a getter on the returned Account demonstrates how many entry points have to be covered, and it is precisely the entry points nobody enumerated that stay open. In the field, look for a handler that owns its own copy of the annotated class, or a same-class call, or an asynchronous executor, or a mapping that invokes the method on a bean obtained outside the container. The observable is the annotation plus a call site that never passes the proxy.

*Disproof:* The claim is false when the method is final or private, since Spring AOP proxies cannot intercept those, and that cuts both ways - it means such a method is never checked regardless of the annotation, but also means the annotation there is inert by construction rather than by bypass. It is also false when method security is backed by AspectJ load-time or compile-time weaving rather than Spring AOP, since weaving instruments the bytecode and self-invocation is then enforced. And the bypass is not remotely reachable on its own: it needs an HTTP-reachable entry that takes the unchecked path, which is the separate condition the report must establish.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.authz.auto.01` — authz: observe, exercise, confirm (goal: `Establish, exercise and confirm a authz condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.**

URL-pattern authorization is evaluated as an ordered list where the first matching rule decides, which makes it a hunt for the earliest permissive entry rather than an assessment of the strictest one. A config that permits /api/** and then adds hasRole('ADMIN') for /api/admin/** looks, at a glance in a diff or a code snippet, like admin routes are locked down. They are not: nothing after the first match runs. Spring Security's own guidance frames the safe shape as the reverse - a catch-all deny at the end, described as a good strategy if you do not want to accidentally forget to update your authorization rules, which only works if the earlier entries are narrow. The field habit this should produce: read the rule list top to bottom and find the first entry whose pattern covers the endpoint under test. Confirming the endpoint sits behind a later rule is not evidence; the endpoint sits behind the earliest matching rule.

*Disproof:* The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.

**A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.**

This is the graphql.org lesson stated as a hunting rule, and it generalises past GraphQL to any API where the same predicate is repeated per handler. The argument graphql.org makes is that placing the ownership check inside the body resolver means the code has to be duplicated for each entry point into the service, and if the logic is not kept perfectly in sync, users see different data depending on which API they use. For the hunter that means a green check on one resolver is not evidence about the others: the primary query has the check, the batched form of the query does not, the nested selection that reaches the same type through a different path does not, and the REST endpoint that wraps the same repository does not. The productive move is to enumerate every path to the protected type - field, query, mutation, subscription, alias, fragment, batch array - and test each independently rather than accepting the schema as the control.

*Disproof:* The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.

**A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.**

Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user. The finding survives only when the authenticated response contains object data the same user was never entitled to, or when the status flips because the endpoint skipped its ownership predicate entirely.

*Disproof:* If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.

**A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.**

Do not discard the report because the handler contains an explicit role or permission check that passed: a check that confirms the caller is a manager without confirming the manager owns that branch is exactly the defect. The report is a false positive instead when the resource returned is one the caller was already entitled to see, when the scope was enforced in a layer you did not exercise, or when your cross-tenant request was rejected and the 200 you saw came from a cached or default response.

*Disproof:* If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.

## Validation

**A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.**

Authentication and authorization are separate stages and most shortcut tests only exercise the first. A tester who removes the cookie, gets a 401, and concludes 'this endpoint is protected' has proved the presence of a session check and nothing else. The authorization question is whether account B, authenticated successfully, is refused the thing account A is allowed to do - and that requires two real accounts, because a single account cannot express a privilege difference. This is why the framework guidance separates the stages explicitly: GraphQL's own sequencing is that execution should begin after authentication middleware confirms the user's identity and passes that information to the GraphQL layer, and only after that do you determine whether the authenticated user is allowed to view the data provided by the specific fields included in the request. Field-level evidence must therefore name both identities and show the same request shape with the same operation, differing only in who is authenticated.

*Disproof:* The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.

**To decide this case, observe: Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user.**

Derived from authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authz.fprule.differs_only_by_auth_state_is_enumeration_not_bypass) states the full boundary.

**A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.**

A broken access control finding is only real when a request issued as an identity that holds no permission for the resource or action still succeeds, so identity substitution on an otherwise-valid request is the test that separates the finding from normal behaviour.

HackTricks reference: broken access control and broken authentication (https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md)

*Disproof:* If the same request replayed as a lower-privileged or unauthenticated identity is rejected or returns only the caller's own authorized data, the permission check is present and the access control claim fails.

## Impact

**An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**

Step: prove the write primitive by comparing a response that differs from a baseline read of the same record set before and after a single injected statement, then escalate only if the changed row is a role or ownership field. The attacker actually gains full administrative access to the application rather than a single record, because the authorization decision is read back out of the database the injection can write; from there application settings, stored data, and secrets reachable by the service are all in scope. Note that an unauthenticated write primitive needs no stolen credential to reach this ceiling, which is what makes the endpoint being unauthenticated by design the multiplier.

*Disproof:* If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898>
- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>
  - <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/862.html>
- **docs.djangoproject.com** (writeup)
  - <https://docs.djangoproject.com/en/5.0/topics/auth/default/>
- **docs.spring.io** (writeup)
  - <https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html>
  - <https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html>
- **graphql.org** (writeup)
  - <https://graphql.org/learn/authorization/>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/aspnet/core/security/authorization>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
- **oreobiscuit.gitbook.io** (reference)
  - <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/broken-access-control-and-broken-authentication.md>
- **owasp.org** (taxonomy)
  - <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/access-control>
- **projectdiscovery.io** (research)
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
