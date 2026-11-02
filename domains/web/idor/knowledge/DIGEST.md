# IDOR / BOLA (Object-Level Authorization)

> surface: `api` · CWE: CWE-639 · OWASP: API1:2023
> maturity: **mature** — 31 items, 19 supported, 3 FP rules, 2 chains

A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.

**Aliases:** broken object level authorization, bola, insecure direct object reference, object level authorization failure, horizontal privilege escalation via id

## Prerequisite

- **IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.**  
  `under_review` · score 0.885 · disproved by: Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
- **An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.**  
  `high_confidence` · score 0.8415 · disproved by: No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
- **IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.**  
  `high_confidence` · score 0.814 · disproved by: All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
- **IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.**  
  `high_confidence` · score 0.8115 · disproved by: An endpoint that accepts an attacker-supplied object id but still refuses cross-account access with 403 or 404 because it verifies the caller's ownership refutes the missing-authorization half of the claim.
  sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>

## Signal

- **A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.**  
  `under_review` · score 0.916 · disproved by: The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control>
- **Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.**  
  `high_confidence` · score 0.893 · disproved by: Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.
  sources: <https://portswigger.net/web-security/graphql> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>

## Technique

- **An insecure direct object reference is proven by requesting an identical endpoint under another user's identifier and receiving that user's record instead of a 403/404.**  
  `high_confidence` · score 0.928 · disproved by: Refuted when the server enforces an ownership check on the object identifier and returns 403/404 for a foreign object, which is the correct behaviour.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Web%20Application%20Attacks.md>
- **The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.**  
  `high_confidence` · score 0.924 · disproved by: Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
- **The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.**  
  `high_confidence` · score 0.8815 · disproved by: Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
  sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
- **Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.**  
  `under_review` · score 0.869 · disproved by: Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
  sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- **Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.**  
  `high_confidence` · score 0.854 · disproved by: Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
  sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
- **Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.**  
  `high_confidence` · score 0.8415 · disproved by: Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://docs.github.com/en/graphql/guides/using-global-node-ids>
- **IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.**  
  `high_confidence` · score 0.8115 · disproved by: A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
  sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
- **Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.**  
  `under_review` · score 0.8055 · disproved by: Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, User IDs should be randomly generated to prevent the creation of predic”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation.**  
  `under_review` · score 0.7745 · disproved by: Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.
  sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
- **The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The system's authorization functionality does not prevent one user from gaining ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>

## Test

- **To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).**  
  `under_review` · score 0.839 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
- **The minimal IDOR proof keeps one authenticated low-privilege session fixed and changes only the object ID, so any difference in the response is attributable to the missing authorization check rather than to session state.**  
  `under_review` · score 0.802 · disproved by: Refuted when the two responses are indistinguishable, or when the second object belongs to the same principal: a different body alone proves nothing about cross-user access.
  sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
- **An IDOR/BOLA finding is only validated with two identities the tester controls, because a hardware serial number seen on the device proves nothing about the server-side ownership check on the object id.**  
  `high_confidence` · score 0.798 · disproved by: A validation run in which the second identity is not under the tester's control, or in which access is judged from a device serial number instead of a cross-account request against the object id, refutes this requirement.
  sources: <https://portswigger.net/web-security/access-control> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning.md>

## Validation

- **A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals.**  
  `high_confidence` · score 0.964 · disproved by: The claim is wrong if the enumeration you used did return objects you do not own - a leaked identifier in a listing response, an export, a sitemap, a sequential id visible in a public page, or a second account you control. In that case the differential is already available and a 404 on some other id is irrelevant. It is also wrong if the endpoint applies authorisation before existence: a handler that checks ownership first and returns 403 for anything not owned, existing or not, produces 404s for nonexistent ids precisely because the check ran - so the 404 is evidence of the check in that ordering. And a 404 can come from a tenant lookup that scopes by account as well as by id, which is a real object gate, so the status code alone never settles it.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.djangoproject.com/en/5.0/topics/db/queries/>
- **Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.**  
  `under_review` · score 0.9065 · disproved by: As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
- **Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.**  
  `high_confidence` · score 0.806 · disproved by: The mutation returns 403/404 and B's object is byte-for-byte unchanged when re-read by B, or B's session shows a reverted/rolled-back state.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>

## Fp Rule

- **Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.**  
  `high_confidence` · score 0.8965 · disproved by: The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
- **A view that passes a model-level permission check is not thereby protected per object: in Django the core framework stores no object-level permissions at all, so an object check that is not explicitly implemented returns empty and the row is served anyway.**  
  `under_review` · score 0.8355 · disproved by: The claim is wrong when the object gate exists somewhere on the path, even if it is not in the permission framework: a queryset filtered by owner, a get_object_or_404 scoped to request.user, a policy-enforced table, or a framework decorator that raises on a failed object check. It is also wrong if you have already demonstrated the negative - an endpoint that returns another user's row when you ask for it, with a valid session and a valid role, is an IDOR regardless of what the permission framework claims to support. And it is wrong as a description of a database-enforced control: PostgreSQL row-level security with a policy on the table means the object gate is enforced by the engine, so the application-level absence of an object check is not an IDOR.
  sources: <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/customizing/>

## Evidence

- **A convincing observation for this class is: Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200.**  
  `under_review` · score 0.8665 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
- **A convincing observation for this class is: A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler.**  
  `under_review` · score 0.8415 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.technique.method_override_and_content_type_swap) states the full boundary.
  sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- **Multiple permissive row-level policies on the same table are OR-combined, so adding a second broad policy silently turns a narrow owner-scoped policy into a wider one without any change to the original statement.**  
  `high_confidence` · score 0.808 · disproved by: The claim does not apply if the policies are restrictive rather than permissive, because restrictive policies combine with AND and can only narrow the set. It also fails if only one policy applies to the operation and role in question - policies can be scoped to specific commands and specific roles, so a SELECT-only broad policy says nothing about UPDATE. And it is not the explanation when the visible rows come from a join or from a security-definer function reading a table with no policy, since that path never passes through the policy combination at all. When in doubt, the decisive artefact is the effective row set for the calling role, not an inference about which policies were OR-combined.
  sources: <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/default/>

## Impact

- **Frame IDOR impact as enumerated cross-tenant records per account class and per operation, and note OWASP rates it easy to exploit, widespread, and easy to detect.**  
  `high_confidence` · score 0.8575 · disproved by: Only your own objects were ever readable/writable, no other account's data was ever returned, and no quantitative scope can be supported beyond a single test record.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>

## Bypass

- **When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.**  
  `under_review` · score 0.8355 · disproved by: The claim is false if the application connects as an unprivileged role with no BYPASSRLS attribute and does not own the table, in which case the policy is genuinely the effective control and every query is filtered by it. It is also false if FORCE ROW LEVEL SECURITY is set on the table, which pulls the owner back under the policy. And it is not by itself a remotely exploitable IDOR: the bypass requires the attacker to be able to make the server issue queries under the privileged role, which is an additional condition - a role configuration weakness rather than a broken object check. Table-level whole-table operations such as TRUNCATE and REFERENCES are also outside policy scope, but that is a different capability from reading another tenant's row.
  sources: <https://portswigger.net/web-security/access-control/idor> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
- **The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.**  
  `high_confidence` · score 0.83 · disproved by: The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>

## Chain Link

- **IDOR chains to full account takeover when the readable object holds credentials, and to vertical privilege escalation when the writable object holds authority.**  
  `high_confidence` · score 0.8575 · disproved by: The exposed object contains no credential, token, session or role-bearing field, and no writable endpoint accepts an ownership or privilege field from the client.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>

## False-positive rules

- **Hypothesis:** GET /api/invoice/{id} returns another user's invoice data
  - **Invalidated by:** Both accounts received byte-identical bodies; the id is resolved within the caller's tenant server-side, so no other tenant's record was reachable
  - **Rule:** A 200 with data is not a finding until the same identifier is shown to resolve differently for a second identity; compare bodies, not status codes

- **Hypothesis:** Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.
  - **Invalidated by:** The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
  - **Rule:** Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.

## Related classes (via chains)

- `jwt` JWT / Token Validation Failures (3 chains)
