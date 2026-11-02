# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 14 (supported 14), FP rules 3, chains 2, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 14 (supported 14), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -98,4 +98,4 @@
 - `jwt` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/idor/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
+Full class document: `domains/web/idor/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
```

## 2026-10-02 19:37 — 40 diff lines
- items: 16 (supported 13), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 14 items, 14 supported, 3 FP rules, 2 chains
+> evidence: 16 items, 13 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -38,10 +38,13 @@
 
 ## Techniques (what to change)
 
-- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.
+- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The system's authorization functionality does not prevent one user from gaining access to ".
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
-- Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.
+- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources. _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
+- Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay. _(unverified)_
   - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
 - Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.
@@ -50,6 +53,12 @@
 - The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.
   - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
+
+## Tests
+
+- To decide this case, observe: ort ticket, an invoice for a unique amount). Record B's object id. Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200. OWASP prescribes exactly this A/B method and requires it across read, create, update, delete, export and admin actions. Attach full request/response pairs for both accounts.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 122 diff lines
- items: 34 (supported 24), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 16 items, 13 supported, 3 FP rules, 2 chains
+> evidence: 34 items, 24 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -26,6 +26,15 @@
 - IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.
   - **Disproof:** All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
+- IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.
+  - **Disproof:** An endpoint that accepts an attacker-supplied object id but still refuses cross-account access with 403 or 404 because it verifies the caller's ownership refutes the missing-authorization half of the claim.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint. _(unverified)_
+  - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.
+  - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 
 ## Recon signals (where to look)
 
@@ -43,25 +52,55 @@
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
 - Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+- An insecure direct object reference is proven by requesting an identical endpoint under another user's identifier and receiving that user's record instead of a 403/404.
+  - **Disproof:** Refuted when the server enforces an ownership check on the object identifier and returns 403/404 for a foreign object, which is the correct behaviour.
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md>
+- IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.
+  - **Disproof:** A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object. _(unverified)_
+  - **Disproof:** Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation. _(unverified)_
+  - **Disproof:** Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check. _(unverified)_
+  - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.
+  - **Disproof:** Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.
+  - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 - Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay. _(unverified)_
   - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
-- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.
+- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated. _(unverified)_
   - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://docs.github.com/en/graphql/guides/using-global-node-ids>
+  - Sources: <https://docs.github.com/en/graphql/guides/using-global-node-ids>
 - The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.
   - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
 
 ## Tests
 
-- To decide this case, observe: ort ticket, an invoice for a unique amount). Record B's object id. Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200. OWASP prescribes exactly this A/B method and requires it across read, create, update, delete, export and admin actions. Attach full request/response pairs for both accounts.
+- To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
+- The minimal IDOR proof keeps one authenticated low-privilege session fixed and changes only the object ID, so any difference in the response is attributable to the missing authorization check rather than to session state.
+  - **Disproof:** Refuted when the two responses are indistinguishable, or when the second object belongs to the same principal: a different body alone proves nothing about cross-user access.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- An IDOR/BOLA finding is only validated with two identities the tester controls, because a hardware serial number seen on the device proves nothing about the server-side ownership check on the object id.
+  - **Disproof:** A validation run in which the second identity is not under the tester's control, or in which access is judged from a device serial number instead of a cross-account request against the object id, refutes this requirement.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning.md>
 
 ## Validation bar (how to prove it)
 
+- A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals. _(unverified)_
+  - **Disproof:** The claim is wrong if the enumeration you used did return objects you do not own - a leaked identifier in a listing response, an export, a sitemap, a sequential id visible in a public page, or a second account you control. In that case the differential is already available and a 404 on some other id is irrelevant. It is also wrong if the endpoint applies authorisation before existence: a handler that checks ownership first and returns 403 for anything not owned, existing or not, produces 404s for nonexistent ids precisely because the check ran - so the 404 is evidence of the check in that ordering. And a 404 can come from a tenant lookup that scopes by account as well as by id, which is a real object gate, so the status code alone never settles it.
+  - Sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.djangoproject.com/en/5.0/topics/db/queries/>
 - Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.
   - **Disproof:** As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
@@ -71,9 +110,24 @@
 
 ## False-positive rules (when to reject it)
 
+- A view that passes a model-level permission check is not thereby protected per object: in Django the core framework stores no object-level permissions at all, so an object check that is not explicitly implemented returns empty and the row is served anyway. _(unverified)_
+  - **Disproof:** The claim is wrong when the object gate exists somewhere on the path, even if it is not in the permission framework: a queryset filtered by owner, a get_object_or_404 scoped to request.user, a policy-enforced table, or a framework decorator that raises on a failed object check. It is also wrong if you have already demonstrated the negative - an endpoint that returns another user's row when you ask for it, with a valid session and a valid role, is an IDOR regardless of what the permission framework claims to support. And it is wrong as a description of a database-enforced control: PostgreSQL row-level security with a policy on the table means the object gate is enforced by the engine, so the application-level absence of an object check is not an IDOR.
+  - Sources: <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/customizing/>
 - Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.
   - **Disproof:** The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
+
+## Evidence requirements
+
+- Multiple permissive row-level policies on the same table are OR-combined, so adding a second broad policy silently turns a narrow owner-scoped policy into a wider one without any change to the original statement.
+  - **Disproof:** The claim does not apply if the policies are restrictive rather than permissive, because restrictive policies combine with AND and can only narrow the set. It also fails if only one policy applies to the operation and role in question - policies can be scoped to specific commands and specific roles, so a SELECT-only broad policy says nothing about UPDATE. And it is not the explanation when the visible rows come from a join or from a security-definer function reading a table with no policy, since that path never passes through the policy combination at all. When in doubt, the decisive artefact is the effective row set for the calling role, not an inference about which policies were OR-combined.
+  - Sources: <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/default/>
+- A convincing observation for this class is: Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
+- A convincing observation for this class is: A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.technique.method_override_and_content_type_swap) states the full boundary.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
 
 ## Impact framing
 
@@ -83,6 +137,9 @@
 
 ## Defence bypasses
 
+- When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.
+  - **Disproof:** The claim is false if the application connects as an unprivileged role with no BYPASSRLS attribute and does not own the table, in which case the policy is genuinely the effective control and every query is filtered by it. It is also false if FORCE ROW LEVEL SECURITY is set on the table, which pulls the owner back under the policy. And it is not by itself a remotely exploitable IDOR: the bypass requires the attacker to be able to make the server issue queries under the privileged role, which is an additional condition - a role configuration weakness rather than a broken object check. Table-level whole-table operations such as TRUNCATE and REFERENCES are also outside policy scope, but that is a different capability from reading another tenant's row.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
 - The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.
... (truncated)
```

## 2026-10-04 00:43 — 222 diff lines
- items: 34 (supported 24), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -20,133 +20,124 @@
 
 ## Prerequisites (do not start without these)
 
-- IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.
+- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.  _(merged 1 duplicate row(s))_
+  - **Disproof:** All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
+- IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.  _(merged 1 duplicate row(s))_
   - **Disproof:** Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
-- IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.
-  - **Disproof:** All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
-  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
-- IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.
+- IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.  _(merged 1 duplicate row(s))_
   - **Disproof:** An endpoint that accepts an attacker-supplied object id but still refuses cross-account access with 403 or 404 because it verifies the caller's ownership refutes the missing-authorization half of the claim.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint. _(unverified)_
-  - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
-- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.
-  - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 
 ## Recon signals (where to look)
 
-- Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.
+- A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
+  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control>
+- Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.  _(merged 1 duplicate row(s))_
   - **Disproof:** Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.
   - Sources: <https://portswigger.net/web-security/graphql> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
-- A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.
-  - **Disproof:** The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
-  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control>
 
 ## Techniques (what to change)
 
-- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data. _(unverified)_
+- An insecure direct object reference is proven by requesting an identical endpoint under another user's identifier and receiving that user's record instead of a 403/404.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the server enforces an ownership check on the object identifier and returns 403/404 for a foreign object, which is the correct behaviour.
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md>
+- IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
+  - Sources: <https://docs.github.com/en/graphql/guides/using-global-node-ids>
+- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+- Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+- The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
+  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
+- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The system's authorization functionality does not prevent one user from gaining access to ".
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
-- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
-- An insecure direct object reference is proven by requesting an identical endpoint under another user's identifier and receiving that user's record instead of a 403/404.
-  - **Disproof:** Refuted when the server enforces an ownership check on the object identifier and returns 403/404 for a foreign object, which is the correct behaviour.
-  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md>
-- IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.
-  - **Disproof:** A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
-  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object. _(unverified)_
-  - **Disproof:** Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
-- Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation. _(unverified)_
-  - **Disproof:** Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.
-  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check. _(unverified)_
-  - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
-- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.
-  - **Disproof:** Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
-- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.
-  - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
-- Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay. _(unverified)_
-  - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
-- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated. _(unverified)_
-  - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
-  - Sources: <https://docs.github.com/en/graphql/guides/using-global-node-ids>
-- The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.
-  - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
-  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
 
 ## Tests
 
-- To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).
+- An IDOR/BOLA finding is only validated with two identities the tester controls, because a hardware serial number seen on the device proves nothing about the server-side ownership check on the object id.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A validation run in which the second identity is not under the tester's control, or in which access is judged from a device serial number instead of a cross-account request against the object id, refutes this requirement.
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning.md>
+- The minimal IDOR proof keeps one authenticated low-privilege session fixed and changes only the object ID, so any difference in the response is attributable to the missing authorization check rather than to session state.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the two responses are indistinguishable, or when the second object belongs to the same principal: a different body alone proves nothing about cross-user access.
+  - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
+- To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-10-04 00:50 — 16 diff lines
- items: 34 (supported 24), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -157,10 +157,9 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. With ONE low-privilege session held fixed, substitute only the object id in path, query, body and header -- one carrier at a time.
+2. The conclusive evidence is a response that differs between two EXISTING identifiers owned by different principals, not a 404 for a missing id.
+3. Use a second account you control to confirm cross-tenant read or write; a device serial or an id visible in a listing is not a cross-account test.
 
 ### What counts as proof
 
```

## 2026-10-04 13:20 — 38 diff lines
- items: 34 (supported 24), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -52,7 +52,7 @@
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
 - Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
   - Sources: <https://docs.github.com/en/graphql/guides/using-global-node-ids>
@@ -61,7 +61,7 @@
   - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 - Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
 - Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
@@ -112,7 +112,7 @@
 
 - A convincing observation for this class is: A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.technique.method_override_and_content_type_swap) states the full boundary.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+  - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
 - A convincing observation for this class is: Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
@@ -130,7 +130,7 @@
 
 - The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.  _(merged 1 duplicate row(s))_
   - **Disproof:** The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.
-  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
 - When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false if the application connects as an unprivileged role with no BYPASSRLS attribute and does not own the table, in which case the policy is genuinely the effective control and every query is filtered by it. It is also false if FORCE ROW LEVEL SECURITY is set on the table, which pulls the owner back under the policy. And it is not by itself a remotely exploitable IDOR: the bypass requires the attacker to be able to make the server issue queries under the privileged role, which is an additional condition - a role configuration weakness rather than a broken object check. Table-level whole-table operations such as TRUNCATE and REFERENCES are also outside policy scope, but that is a different capability from reading another tenant's row.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
```

## 2026-10-04 19:46 — 9 diff lines
- items: 34 (supported 24), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -170,6 +170,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/idor/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 33 diff lines
- items: 34 (supported 26), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 34 items, 24 supported, 3 FP rules, 2 chains
+> evidence: 34 items, 26 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -50,8 +50,8 @@
 - IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.  _(merged 1 duplicate row(s))_
   - **Disproof:** A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
+- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, User IDs should be randomly generated to prevent the creation of predic”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
@@ -71,8 +71,8 @@
 - The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.  _(merged 1 duplicate row(s))_
   - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
-- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The system's authorization functionality does not prevent one user from gaining access to ".
+- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The system's authorization functionality does not prevent one user from gaining ”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
 
 ## Tests
```

## 2026-10-07 00:40 — 2 DoD-session rules (pre-gate, no skillgen run)
- items: unchanged; 2 FP-kill rules filed in `research/pending/fp/fp-dod-session-2026-10-03.json` (source: `/mnt/e/bugbounty/DOD/sessions/2026-10-03-kh`)

```diff
--- idor@current
+++ idor@pending
+- idor.fprule.webforms_viewstate_normalised_before_hash: ASP.NET rotates __VIEWSTATE per request, so raw per-request SHA diff is session-token noise. Fetch the same URL twice first; hash only after stripping viewstate/script/style, and treat a one-word step-label diff as a UI selector, not a record.
+- idor.fprule.foia_published_catalog_by_design: on FOIA/document apps the parameter may be real and id-scoped yet address only published records. Kill unless a docid serves content absent from the app's own public catalog and a Distribution-A by-design reading is excluded.
```

## 2026-10-28 12:46 — 20 diff lines
- items: 34 (supported 27), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 34 items, 26 supported, 3 FP rules, 2 chains
+> evidence: 34 items, 27 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -20,7 +20,7 @@
 
 ## Prerequisites (do not start without these)
 
-- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.  _(merged 2 duplicate row(s))_ _(unverified)_
+- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.  _(merged 2 duplicate row(s))_
   - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 - IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.  _(merged 1 duplicate row(s))_
```

## 2026-10-28 14:45 — 41 diff lines
- items: 31 (supported 26), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 34 items, 27 supported, 3 FP rules, 2 chains
+> evidence: 31 items, 26 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -20,9 +20,9 @@
 
 ## Prerequisites (do not start without these)
 
-- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.  _(merged 2 duplicate row(s))_
+- An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.  _(merged 1 duplicate row(s))_
   - **Disproof:** No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
-  - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://portswigger.net/web-security/access-control> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 - IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.  _(merged 1 duplicate row(s))_
   - **Disproof:** All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
@@ -56,7 +56,7 @@
 - Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
   - Sources: <https://docs.github.com/en/graphql/guides/using-global-node-ids>
-- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.  _(merged 2 duplicate row(s))_ _(unverified)_
+- Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.  _(merged 1 duplicate row(s))_
   - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 - Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -65,7 +65,7 @@
 - Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.  _(merged 2 duplicate row(s))_ _(unverified)_
+- The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.  _(merged 1 duplicate row(s))_
   - **Disproof:** Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
 - The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.  _(merged 1 duplicate row(s))_
```

## 2026-10-28 17:55 — 35 diff lines
- items: 31 (supported 28), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 31 items, 26 supported, 3 FP rules, 2 chains
+> evidence: 31 items, 28 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -53,9 +53,9 @@
 - Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, User IDs should be randomly generated to prevent the creation of predic”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_ _(unverified)_
+- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_
   - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
-  - Sources: <https://docs.github.com/en/graphql/guides/using-global-node-ids>
+  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://docs.github.com/en/graphql/guides/using-global-node-ids>
 - Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.  _(merged 1 duplicate row(s))_
   - **Disproof:** Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html> · <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
@@ -89,9 +89,9 @@
 
 ## Validation bar (how to prove it)
 
-- A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals.  _(merged 1 duplicate row(s))_ _(unverified)_
+- A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong if the enumeration you used did return objects you do not own - a leaked identifier in a listing response, an export, a sitemap, a sequential id visible in a public page, or a second account you control. In that case the differential is already available and a 404 on some other id is irrelevant. It is also wrong if the endpoint applies authorisation before existence: a handler that checks ownership first and returns 403 for anything not owned, existing or not, produces 404s for nonexistent ids precisely because the check ran - so the 404 is evidence of the check in that ordering. And a 404 can come from a tenant lookup that scopes by account as well as by id, which is a real object gate, so the status code alone never settles it.
-  - Sources: <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.djangoproject.com/en/5.0/topics/db/queries/>
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.djangoproject.com/en/5.0/topics/db/queries/>
 - Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.  _(merged 1 duplicate row(s))_
   - **Disproof:** As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
```

## 2026-10-31 06:41 — 82 diff lines
- items: 31 (supported 19), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 31 items, 28 supported, 3 FP rules, 2 chains
+> evidence: 31 items, 19 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -26,7 +26,7 @@
 - IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.  _(merged 1 duplicate row(s))_
   - **Disproof:** All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
-- IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.  _(merged 1 duplicate row(s))_
+- IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
 - IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.  _(merged 1 duplicate row(s))_
@@ -35,7 +35,7 @@
 
 ## Recon signals (where to look)
 
-- A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.  _(merged 1 duplicate row(s))_
+- A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control>
 - Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.  _(merged 1 duplicate row(s))_
@@ -50,7 +50,7 @@
 - IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.  _(merged 1 duplicate row(s))_
   - **Disproof:** A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_
+- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, User IDs should be randomly generated to prevent the creation of predic”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.  _(merged 1 duplicate row(s))_
@@ -80,10 +80,10 @@
 - An IDOR/BOLA finding is only validated with two identities the tester controls, because a hardware serial number seen on the device proves nothing about the server-side ownership check on the object id.  _(merged 1 duplicate row(s))_
   - **Disproof:** A validation run in which the second identity is not under the tester's control, or in which access is judged from a device serial number instead of a cross-account request against the object id, refutes this requirement.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning.md>
-- The minimal IDOR proof keeps one authenticated low-privilege session fixed and changes only the object ID, so any difference in the response is attributable to the missing authorization check rather than to session state.  _(merged 1 duplicate row(s))_
+- The minimal IDOR proof keeps one authenticated low-privilege session fixed and changes only the object ID, so any difference in the response is attributable to the missing authorization check rather than to session state.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the two responses are indistinguishable, or when the second object belongs to the same principal: a different body alone proves nothing about cross-user access.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
-- To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).  _(merged 1 duplicate row(s))_
+- To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
 
@@ -92,7 +92,7 @@
 - A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong if the enumeration you used did return objects you do not own - a leaked identifier in a listing response, an export, a sitemap, a sequential id visible in a public page, or a second account you control. In that case the differential is already available and a 404 on some other id is irrelevant. It is also wrong if the endpoint applies authorisation before existence: a handler that checks ownership first and returns 403 for anything not owned, existing or not, produces 404s for nonexistent ids precisely because the check ran - so the 404 is evidence of the check in that ordering. And a 404 can come from a tenant lookup that scopes by account as well as by id, which is a real object gate, so the status code alone never settles it.
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://docs.djangoproject.com/en/5.0/topics/auth/default/> · <https://docs.djangoproject.com/en/5.0/topics/db/queries/>
-- Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.  _(merged 1 duplicate row(s))_
+- Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
 - Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.  _(merged 1 duplicate row(s))_
@@ -110,10 +110,10 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.technique.method_override_and_content_type_swap) states the full boundary.
   - Sources: <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
-- A convincing observation for this class is: Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
 - Multiple permissive row-level policies on the same table are OR-combined, so adding a second broad policy silently turns a narrow owner-scoped policy into a wider one without any change to the original statement.  _(merged 1 duplicate row(s))_
@@ -131,7 +131,7 @@
 - The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.  _(merged 1 duplicate row(s))_
   - **Disproof:** The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
-- When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.  _(merged 1 duplicate row(s))_
+- When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false if the application connects as an unprivileged role with no BYPASSRLS attribute and does not own the table, in which case the policy is genuinely the effective control and every query is filtered by it. It is also false if FORCE ROW LEVEL SECURITY is set on the table, which pulls the owner back under the policy. And it is not by itself a remotely exploitable IDOR: the bypass requires the attacker to be able to make the server issue queries under the privileged role, which is an additional condition - a role configuration weakness rather than a broken object check. Table-level whole-table operations such as TRUNCATE and REFERENCES are also outside policy scope, but that is a different capability from reading another tenant's row.
   - Sources: <https://portswigger.net/web-security/access-control/idor> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
 
```
