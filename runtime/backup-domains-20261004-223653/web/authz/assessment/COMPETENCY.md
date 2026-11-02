# Methodology — Missing Function-Level Authorization

> Derived from 11 verified items. Regenerate with `python -m wks.methodgen --class authz --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**References.** CWE-862 · API5:2023

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Public writeup evidence for authz: self-registration onto a data platform.**

HARVESTED FROM bugbountydaily RSS -> https://bobdahacker.com/blog/fifa-hack
Reason it matters: self-registration onto a data platform.

If an attacker pushed video to one of those RTMP endpoints with the stream key (which is RIGHT THERE in the URL), they would replace the camera feed .

- *Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
- *Evidence:* high_confidence — [bobdahacker.com](https://bobdahacker.com/blog/fifa-hack); [portswigger.net](https://portswigger.net/web-security/access-control)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A 401 on an endpoint proves authentication is enforced and says nothing about authorization; the authorization question can only be answered by two accounts with different privileges and the same request.**

Authentication and authorization are separate stages and most shortcut tests only exercise the first. A tester who removes the cookie, gets a 401, and concludes 'this endpoint is protected' has proved the presence of a session check and nothing else. The authorization question is whether account B, authenticated successfully, is refused the thing account A is allowed to do - and that requires two real accounts, because a single account cannot express a privilege difference. This is why the framework guidance separates the stages explicitly: GraphQL's own sequencing is that execution should begin after authentication middleware confirms the user's identity and passes that information to the GraphQL layer, and only after that do you determine whether the authenticated user is allowed to view the data provided by the specific fields included in the request. Field-level evidence must therefore name both identities and show the same request shape with the same operation, differing only in who is authenticated.

- *Disproof:* The rule does not apply when the endpoint is unauthenticated by design - a genuinely public resource returns the same thing to everyone, and there is no authorization boundary to cross, so a single account suffices. It also weakens if the privilege difference is carried in something other than the identity, such as a per-request role header or a tenant selected by a parameter, in which case varying that value is the equivalent of varying the account. And if the two accounts happen to share a role but differ in ownership, that is a valid two-account test for object-level authorization even though it proves nothing about role-based authorization - the report must say which one it demonstrated.
- *Evidence:* high_confidence — [docs.spring.io](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html); [graphql.org](https://graphql.org/learn/authorization/)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.**

Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user. The finding survives only when the authenticated response contains object data the same user was never entitled to, or when the status flips because the endpoint skipped its ownership predicate entirely.

- *Disproof:* If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515); [httpwg.org](https://httpwg.org/specs/rfc9110.html)

**A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.**

Do not discard the report because the handler contains an explicit role or permission check that passed: a check that confirms the caller is a manager without confirming the manager owns that branch is exactly the defect. The report is a false positive instead when the resource returned is one the caller was already entitled to see, when the scope was enforced in a layer you did not exercise, or when your cross-tenant request was rejected and the 200 you saw came from a cached or default response.

- *Disproof:* If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**A field-level check implemented inside one resolver does not evidence an access-control control, because the same rule duplicated across every entry point drifts and leaves one entry unguarded.**

This is the graphql.org lesson stated as a hunting rule, and it generalises past GraphQL to any API where the same predicate is repeated per handler. The argument graphql.org makes is that placing the ownership check inside the body resolver means the code has to be duplicated for each entry point into the service, and if the logic is not kept perfectly in sync, users see different data depending on which API they use. For the hunter that means a green check on one resolver is not evidence about the others: the primary query has the check, the batched form of the query does not, the nested selection that reaches the same type through a different path does not, and the REST endpoint that wraps the same repository does not. The productive move is to enumerate every path to the protected type - field, query, mutation, subscription, alias, fragment, batch array - and test each independently rather than accepting the schema as the control.

- *Disproof:* The claim is false when the check is centralised rather than repeated: a single repository or service method that owns the predicate, a database row-level policy, or a framework directive that is applied by an automated rule to every field of the type. In those cases the duplication problem does not arise and the green check on one resolver is genuinely representative. It is also false as a description of a defect in the schema: a directive present on one field of a type is not, on its own, a vulnerability - the finding needs a concrete field or operation that reaches the data without the check.
- *Evidence:* high_confidence — [graphql.org](https://graphql.org/learn/authorization/); [portswigger.net](https://portswigger.net/web-security/access-control)

**A URL-pattern authorization list whose first rule is permitAll is not a partial protection that 'mostly works' - the first match wins, so every later rule is dead code and the whole prefix is public.**

URL-pattern authorization is evaluated as an ordered list where the first matching rule decides, which makes it a hunt for the earliest permissive entry rather than an assessment of the strictest one. A config that permits /api/** and then adds hasRole('ADMIN') for /api/admin/** looks, at a glance in a diff or a code snippet, like admin routes are locked down. They are not: nothing after the first match runs. Spring Security's own guidance frames the safe shape as the reverse - a catch-all deny at the end, described as a good strategy if you do not want to accidentally forget to update your authorization rules, which only works if the earlier entries are narrow. The field habit this should produce: read the rule list top to bottom and find the first entry whose pattern covers the endpoint under test. Confirming the endpoint sits behind a later rule is not evidence; the endpoint sits behind the earliest matching rule.

- *Disproof:* The claim is false when the framework composes rules conjunctively rather than first-match - Spring's authorizeHttpRequests is explicitly first-match-wins, but other frameworks intersect a global role requirement with per-route permissions, and several stacks have an authenticated() default that ANDs with the specific rule rather than replacing it. It is also false when the permissive pattern does not actually cover the endpoint: a pattern with a trailing-segment wildcard like /api/* may not match /api/admin/users, and path-parameter normalisation differences between the matcher and the servlet container routinely produce a rule that looks like it matches and does not. And a genuinely enforced control exists if the endpoint is additionally covered by a method-level annotation or a database policy, in which case the HTTP rule is not the only gate.
- *Evidence:* high_confidence — [docs.spring.io](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html); [graphql.org](https://graphql.org/learn/authorization/)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Method-level authorization annotations are enforced by an interceptor around the bean, so an internal call path that reaches the annotated method without going through that bean - a self-invocation, a direct construction, a scheduled task, a deserialiser, or a second bean holding a reference - executes it completely unchecked.**

The mechanism behind Spring's method security is that @EnableMethodSecurity publishes advisors which are woven into the set of advice that AuthorizationProxyFactory adds when proxying an object, and expressions using returnObject or filterObject sit behind the proxy so they have full access to the object. That 'behind the proxy' wording is the whole vulnerability class: the annotation is not a property of the code, it is a property of one call path. Spring's own idiom of annotating both a service method and a getter on the returned Account demonstrates how many entry points have to be covered, and it is precisely the entry points nobody enumerated that stay open. In the field, look for a handler that owns its own copy of the annotated class, or a same-class call, or an asynchronous executor, or a mapping that invokes the method on a bean obtained outside the container. The observable is the annotation plus a call site that never passes the proxy.

- *Disproof:* The claim is false when the method is final or private, since Spring AOP proxies cannot intercept those, and that cuts both ways - it means such a method is never checked regardless of the annotation, but also means the annotation there is inert by construction rather than by bypass. It is also false when method security is backed by AspectJ load-time or compile-time weaving rather than Spring AOP, since weaving instruments the bytecode and self-invocation is then enforced. And the bypass is not remotely reachable on its own: it needs an HTTP-reachable entry that takes the unchecked path, which is the separate condition the report must establish.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/topics/auth/default/); [docs.spring.io](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Impact

_What is actually demonstrable, and what to stop claiming._

**An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**

Step: prove the write primitive by comparing a response that differs from a baseline read of the same record set before and after a single injected statement, then escalate only if the changed row is a role or ownership field. The attacker actually gains full administrative access to the application rather than a single record, because the authorization decision is read back out of the database the injection can write; from there application settings, stored data, and secrets reachable by the service are all in scope. Note that an unauthenticated write primitive needs no stolen credential to reach this ceiling, which is what makes the endpoint being unauthenticated by design the multiplier.

- *Disproof:* If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898); [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
