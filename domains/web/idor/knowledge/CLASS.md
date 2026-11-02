# IDOR / BOLA (Object-Level Authorization)

## Definition

A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.

- **CWE:** CWE-639
- **OWASP:** API1:2023
- **Surface:** api
- **Aliases:** ["broken object level authorization", "bola", "insecure direct object reference", "object level authorization failure", "horizontal privilege escalation via id"]

Canonical home for `idor`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.**

Enumerate every identifier carrier in the app: path segments (GET /invoices/1043), query params (?invoice_id=1043 or ?customer_number=132355), JSON body fields ("documentId", "owner_id"), headers (X-Account-Id, X-Request-Id), hidden form fields (<input type="hidden" name="user_id" value="12345">) and cookies. If no client-controlled key reaches the data access path, there is no IDOR surface. Static paths with no key (GET /documents/annual-report.pdf) are still IDOR-prone because the filename itself acts as the reference.

*Disproof:* Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.

**IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.**

Two multipliers make IDOR cheap to automate: nested references such as GET /invoices/{invoiceId}/items/{itemId} or /shops/{shopName}/revenue_data.json where you can hold one leg constant and vary the other, and enumerable keys where ids are sequential integers (CWE-639 lists sequential or easily-guessable ids as a manifestation). Note a GUID key does NOT remove the flaw: OWASP states access control checks remain essential even with complex identifiers, so treat unguessable ids as a hunt-priority reducer, never as a disproof.

*Disproof:* All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.

**IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.**

IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.

HackTricks reference: IDOR (pentesting-web/idor.md)

*Disproof:* An endpoint that accepts an attacker-supplied object id but still refuses cross-account access with 403 or 404 because it verifies the caller's ownership refutes the missing-authorization half of the claim.

**An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.**

An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

*Disproof:* No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.

**An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.**

An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

*Disproof:* No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.

## Attack Surface

Surface: **api**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.**

If a list endpoint returns ids 1,2,4 you have a delisted record at 3 and can query it directly to recover non-listed state. Also harvest every identifier echoed in responses: owner_id, user_id, tenant_id, parent_id, invoice_id, avatar object keys. Those values are your wordlist for the substitution sweep. WSTG's GraphQL case shows the same shape: query the auth/resource set, extract foreign ids and tokens, then act as that principal.

*Disproof:* Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.

**A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.**

Take a legitimate request as user A, record status/length/body hash, then replay the exact request in Repeater with the id replaced by an id from account B. OWASP notes the server response is usually enough to tell whether the request succeeded. Diff on more than status: compare Content-Length, JSON keys, presence of other-user PII (email, address, last4), and any owner_id/user_id echoed back. A 200 whose body length matches A's template but contains B's identifiers is a confirmed BOLA, not just an enumeration hint.

*Disproof:* The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.

**Multiple permissive row-level policies on the same table are OR-combined, so adding a second broad policy silently turns a narrow owner-scoped policy into a wider one without any change to the original statement.**

The mechanic to check when a scoped policy appears to have stopped working is how policies compose. PostgreSQL combines multiple applicable policies using OR for permissive policies, which are the default, and AND for restrictive ones. That means a table that once had one policy of user_name = current_user and later gained a second permissive policy for, say, a support role now returns the union of both row sets - and the original owner policy is still present, still correct, still syntactically valid. Nothing in the policy that was written first changed. The field consequence is that policy text is not sufficient evidence: what matters is the effective result set under the role the application actually uses. A convincing observation is the query result itself, showing a row the calling principal should not see, ideally reproduced with the application's own credentials rather than with an admin session.

*Disproof:* The claim does not apply if the policies are restrictive rather than permissive, because restrictive policies combine with AND and can only narrow the set. It also fails if only one policy applies to the operation and role in question - policies can be scoped to specific commands and specific roles, so a SELECT-only broad policy says nothing about UPDATE. And it is not the explanation when the visible rows come from a join or from a security-definer function reading a table with no policy, since that path never passes through the policy combination at all. When in doubt, the decisive artefact is the effective row set for the calling role, not an inference about which policies were OR-combined.

**A convincing observation for this class is: Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200.**

Derived from idor.validation.two_account_cross_tenant_read, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.

**A convincing observation for this class is: A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler.**

Derived from idor.technique.method_override_and_content_type_swap, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (idor.technique.method_override_and_content_type_swap) states the full boundary.

## Exploitation

**The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.**

al, close it 
var modal = document.getElementById("customFilterModal"); 
window.onclick = function(event) { 
 if (event.target == document.getElementById("customFilterModal")) { 
 modal.style.display = "none"; 
 document.getElementById("customFilterLeftBox").innerHTML = ""; 
 document.getElementById("customFilterRightBox").innerHTML = ""; 
 } 
} 
 

 

 
 
 
 
 

 
 
 
 
 
 
 
 Description
 
 
 
 The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data. 
 
 
 

 

 
 
 
 
 
 
 
 Extended Description
 
 
 
 
 
 Retrieval of a user record occurs in the system based on some key value that is under user control. The key would typically identify a user-related record stored in the system and would be used to lookup that record for presentation to the user. It is likely that an attacker would have to be an authenticated user in the system. However, th

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The system's authorization functionality does not prevent one user from gaining ”) does not occur under a test that isolates that control.

**Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.**

ack and forth between the client and server when transmitting and receiving requests. Sessions should be unique per user and computationally very difficult to predict. The Session Management Cheat Sheet contains further guidance on the best practices in this area. 
 Authentication General Guidelines ¶ 
 User IDs ¶ 
 The primary function of a User ID is to uniquely identify a user within a system. Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources. 
 Usernames ¶ 
 Usernames are easy-to-remember identifiers chosen by the user and used for identifying themselves when logging into a system or service. The terms User ID and username might be used interchangeably if the username chosen by the user also serves as their unique identifier within the system. 
 Users should be permitted to use their email address as a username, provided the email is

*Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, User IDs should be randomly generated to prevent the creation of predic”) does not occur under a test that isolates that control.

**An insecure direct object reference is proven by requesting an identical endpoint under another user's identifier and receiving that user's record instead of a 403/404.**

In practice on HTB this shows up as: The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as `User1`. However, with these details at hand, we can try repeating the same API call while logged in as `User2` to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the API call but has no access control on the back-end to compare the caller's session with the data being called.
<u>Mass IDOR Enumeration</u>:
We can try manually accessing other employee documents with `uid=3`, `uid=4`, and so on. However, manually accessing files is not efficient in a real work environment with hundreds or thousands of employees. So, we can either use a tool like `Burp Intruder` or `ZAP Fuzzer` to retrieve all files or write a small bash script to download all files.

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Web Application Attacks.md (3660 words, classified web).

*Disproof:* Refuted when the server enforces an ownership check on the object identifier and returns 403/404 for a foreign object, which is the correct behaviour.

**IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.**

IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.

HackTricks reference: IDOR (pentesting-web/idor.md)

*Disproof:* A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.

**The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.**

The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

*Disproof:* Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.

**Predictable object identifiers are what make an access-control flaw reachable at scale, so enumeration of the id space is part of the test rather than an optimisation.**

HackTricks reference: IDOR - testing guidance

*Disproof:* Refuted when identifiers are non-sequential, non-guessable, and still authorised server-side: an unauthorised 200 that returns another user's object is the only evidence, not a low entropy id.

**Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.**

Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

*Disproof:* Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.

**The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.**

The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

*Disproof:* Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.

**Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.**

Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

*Disproof:* Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.

**Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.**

A gateway rule like DENY: POST, /admin/deleteUser, managers is enforced at the platform layer; replay the identical body as GET, or as an unrecognised verb like POSTX that falls through to a generic handler. Test X-HTTP-Method-Override: DELETE and _method=DELETE on a POST. Re-POST a mutation as application/x-www-form-urlencoded instead of application/json - GraphQL endpoints accepting form-encoded POST route past checks that inspect JSON only.

*Disproof:* Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.

**Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.**

On GET /invoices/{id}/items/{itemId}, fix itemId to a value you own while varying the parent id, then flip the legs. Probe routing tolerance: trailing slash, Spring useSuffixPatternMatch suffixes (/invoices/4471/items/9001.json), case variants. For GraphQL/Relay, REST returns node_id ("MDQ6VXNlcjU4MzIzMQ=="); base64-decode it to recover type and internal id, then query node(id:"..."){ __typename } and read fields with an inline fragment. node/nodes fields often exist unintentionally.

*Disproof:* Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.

**Nested references and URL-matching discrepancies (trailing slash, extension suffix, case) let a validated parent path reach an unvalidated child object.**

On GET /invoices/{id}/items/{itemId}, fix itemId to a value you own while varying the parent id, then flip the legs: keep your invoice id and iterate itemId. If the handler authorizes only the parent, the child is readable cross-tenant. Also probe routing tolerance: /invoices/4471/items/9001/ , /invoices/4471/items/9001.json (Spring useSuffixPatternMatch behaviour), and /Invoices/4471/Items/9001 - front-end ACL rules keyed on the literal path diverge from the backend route matcher.

*Disproof:* Both legs of every nested path are independently authorized against the session owner, and trailing-slash, extension-suffix and case variants are rejected with 404 rather than routed.

**The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.**

Baseline: GET /api/v1/customers/4471 with user A's Authorization: Bearer <jwt>. Then in Repeater change only the id, keeping method, headers, cookie and CSRF token fixed. Repeat across carriers for the same object: GET /customer_account?customer_number=132355, POST body {"invoiceId": 8830}, header X-Account-Id: 99. OWASP's own scenario is exactly this - take the shop-name list from one endpoint and substitute each name into /shops/{shopName}/revenue_data.json. Fixing everything except the key isolates authorization from every other variable.

*Disproof:* Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.

## Variations

**When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.**

This is the strongest architectural bypass in object-level authorization and it is invisible from HTTP behaviour alone, because it shows up as 'the data is right' in every test. PostgreSQL states it plainly: superusers and roles with the BYPASSRLS attribute always bypass the row security system, table owners normally bypass it too, and the owner can opt in with FORCE ROW LEVEL SECURITY. Policy expressions run with the privileges of the user running the query, which adds the second-order case: a policy that calls a security-definer function can read data the calling user could not. When you are assessing an application that relies on the database for tenant isolation, the questions are therefore about the connection role, not about the policy text. Reachability of a privileged role - a migration account reused at runtime, an admin tooling endpoint that runs under the same credentials, a superuser connection string in a config file or an SSRF-reachable internal service - converts a 'protected' table into a fully readable one.

*Disproof:* The claim is false if the application connects as an unprivileged role with no BYPASSRLS attribute and does not own the table, in which case the policy is genuinely the effective control and every query is filtered by it. It is also false if FORCE ROW LEVEL SECURITY is set on the table, which pulls the owner back under the policy. And it is not by itself a remotely exploitable IDOR: the bypass requires the attacker to be able to make the server issue queries under the privileged role, which is an additional condition - a role configuration weakness rather than a broken object check. Table-level whole-table operations such as TRUNCATE and REFERENCES are also outside policy scope, but that is a different capability from reading another tenant's row.

**The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.**

Three bypasses. (1) Check-after-use: the handler reads and returns the row first, verifies ownership after, so the body leaks before the check throws - a 200 with complete data and an authorization error in the tail. (2) Unchecked method: only POST is gated at the gateway; PATCH/PUT/DELETE reach the handler. (3) Mass assignment: POST /api/host/approve_booking {"approved":true} becomes {"approved":true,"owner_id":4471}.

*Disproof:* The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `idor-to-account-takeover` — IDOR on a password/session object to account takeover (goal: `account_takeover`)
- `jwt-weak-verification-to-impersonation` — jwt-weak-verification-to-impersonation (goal: `account_takeover`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A view that passes a model-level permission check is not thereby protected per object: in Django the core framework stores no object-level permissions at all, so an object check that is not explicitly implemented returns empty and the row is served anyway.**

The trap in IDOR hunting is that a framework's permission framework gives you real, working, visible evidence of authorization - and that evidence is about the model type, not the row. Django is explicit: its permission framework has a foundation for object permissions but no implementation in core, so checking for object permissions always returns False or an empty list depending on the check performed, and it is the authentication backend that receives obj and user_obj and decides. Rails has the same shape, where a controller can enforce a model permission and still hand any record of that model to any authenticated user. So the field rule is: a 200 with a valid session and a passing role check proves the role gate, and says nothing about the ownership gate. The question you must answer separately is whether this particular handler narrowed the queryset to objects belonging to the requesting principal - and a role check in the code is never evidence that it did.

*Disproof:* The claim is wrong when the object gate exists somewhere on the path, even if it is not in the permission framework: a queryset filtered by owner, a get_object_or_404 scoped to request.user, a policy-enforced table, or a framework decorator that raises on a failed object check. It is also wrong if you have already demonstrated the negative - an endpoint that returns another user's row when you ask for it, with a valid session and a valid role, is an IDOR regardless of what the permission framework claims to support. And it is wrong as a description of a database-enforced control: PostgreSQL row-level security with a policy on the table means the object gate is enforced by the engine, so the application-level absence of an object check is not an IDOR.

**Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.**

Two frequent rejections. (1) Public-by-design: catalogue SKUs, published blog posts, delisted-but-public product rows, shared team boards and public invoice PDFs are readable by any authenticated user - confirm with the app's own UI that no privacy setting exists, and that OWASP's guidance to expose only fields the requester may read is already met. (2) Own-tenant: on multi-tenant SaaS you and the other user may share org_id; verify the ownership field (owner_id, tenant_id, org_id) in the returned payload actually differs before reporting.

*Disproof:* The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
**Hypothesis:** Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.
- Invalidated by: The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
- **Rejection rule:** Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.

**Hypothesis:** GET /api/invoice/{id} returns another user's invoice data
- Invalidated by: Both accounts received byte-identical bodies; the id is resolved within the caller's tenant server-side, so no other tenant's record was reachable
- **Rejection rule:** A 200 with data is not a finding until the same identifier is shown to resolve differently for a second identity; compare bodies, not status codes

## Validation

**A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals.**

IDOR false positives come from testing against identifiers that do not exist. If /invoice/999999 returns 404, a tester may read that as the owner check working - but the handler may simply be doing get(pk) and letting the DoesNotExist path produce the 404, with no ownership predicate anywhere in the query. The discriminating observation is a comparison between two real objects: request your own object and note the full response, then request the other user's object you actually know exists (obtained from a leaked list, an export, a shared link, an invite, or a second account of your own) and note that response. If the second returns the object, the check is absent. If it returns a different shape - 403, 404, or a redacted body - the check is present. Reporting the negative case is also worth doing explicitly: 'I could not find an identifier of another principal's object' is a materially different statement from 'the endpoint enforces ownership', and only the first is what you actually proved.

*Disproof:* The claim is wrong if the enumeration you used did return objects you do not own - a leaked identifier in a listing response, an export, a sitemap, a sequential id visible in a public page, or a second account you control. In that case the differential is already available and a 404 on some other id is irrelevant. It is also wrong if the endpoint applies authorisation before existence: a handler that checks ownership first and returns 403 for anything not owned, existing or not, produces 404s for nonexistent ids precisely because the check ran - so the 404 is evidence of the check in that ordering. And a 404 can come from a tenant lookup that scopes by account as well as by id, which is a real object gate, so the status code alone never settles it.

**Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.**

Register User A and User B, both low-privilege and in the same role. As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount). Record B's object id. Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200. OWASP prescribes exactly this A/B method and requires it across read, create, update, delete, export and admin actions. Attach full request/response pairs for both accounts.

*Disproof:* As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.

**Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.**

As B, capture a mutable field on B's object (note title, shipping address, workflow state, visibility flag). As A, issue the write against B's id: PATCH /invoices/8830 {"status":"approved"}, or the GraphQL mutation deleteReports(reportKeys:["<B_DOCUMENT_ID>"]). Do not stop at a 200 - log back in as B in a clean browser and screenshot the mutated field, or confirm via an audit-log/read API. Write IDOR escalates severity because it turns a read bug into integrity loss and deletion.

*Disproof:* The mutation returns 403/404 and B's object is byte-for-byte unchanged when re-read by B, or B's session shows a reverted/rolled-back state.

**To decide this case, observe: As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount).**

Derived from idor.validation.two_account_cross_tenant_read, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (idor.validation.two_account_cross_tenant_read) states the full boundary.

**The minimal IDOR proof keeps one authenticated low-privilege session fixed and changes only the object ID, so any difference in the response is attributable to the missing authorization check rather than to session state.**

HackTricks reference: IDOR - proof of concept shape

*Disproof:* Refuted when the two responses are indistinguishable, or when the second object belongs to the same principal: a different body alone proves nothing about cross-user access.

**An IDOR/BOLA finding is only validated with two identities the tester controls, because a hardware serial number seen on the device proves nothing about the server-side ownership check on the object id.**

An IDOR/BOLA finding is only validated with two identities the tester controls, because a hardware serial number seen on the device proves nothing about the server-side ownership check on the object id.

HackTricks reference: Wi-Fi Direct, Aware, AWDL and IoT Provisioning (generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning.md)

*Disproof:* A validation run in which the second identity is not under the tester's control, or in which access is judged from a device serial number instead of a cross-account request against the object id, refutes this requirement.

## Impact

**Frame IDOR impact as enumerated cross-tenant records per account class and per operation, and note OWASP rates it easy to exploit, widespread, and easy to detect.**

OWASP scores API1:2023 Exploitability Easy, Prevalence Widespread, Detectability Easy, Technical Moderate - state that so the triager sees the baseline. Then quantify only what you showed: "authenticated user read private invoices of one of two test tenants; sequential id space implies ~N records per tenant; write variant permitted status change and delete." Business impact follows the data class. Never claim bulk extraction you did not perform.

*Disproof:* Only your own objects were ever readable/writable, no other account's data was ever returned, and no quantitative scope can be supported beyond a single test record.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/639.html>
- **docs.djangoproject.com** (writeup)
  - <https://docs.djangoproject.com/en/5.0/topics/auth/customizing/>
  - <https://docs.djangoproject.com/en/5.0/topics/auth/default/>
  - <https://docs.djangoproject.com/en/5.0/topics/db/queries/>
- **docs.github.com** (docs)
  - <https://docs.github.com/en/graphql/guides/using-global-node-ids>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/idor/idor.md>
- **owasp.org** (taxonomy)
  - <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
  - <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **portswigger.net** (taxonomy)
  - <https://portswigger.net/web-security/access-control>
  - <https://portswigger.net/web-security/access-control/idor>
  - <https://portswigger.net/web-security/graphql>
- **postgresql.org** (research)
  - <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md>
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Web%20Application%20Attacks.md>
- **wstg.owasp.org** (research)
  - <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
