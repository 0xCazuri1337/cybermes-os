# Methodology — IDOR / BOLA (Object-Level Authorization)

> Derived from 24 verified items. Regenerate with `python -m wks.methodgen --class idor --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.

**References.** CWE-639 · API1:2023

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.**

Enumerate every identifier carrier in the app: path segments (GET /invoices/1043), query params (?invoice_id=1043 or ?customer_number=132355), JSON body fields ("documentId", "owner_id"), headers (X-Account-Id, X-Request-Id), hidden form fields (<input type="hidden" name="user_id" value="12345">) and cookies. If no client-controlled key reaches the data access path, there is no IDOR surface. Static paths with no key (GET /documents/annual-report.pdf) are still IDOR-prone because the filename itself acts as the reference.

- *Disproof:* Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control/idor)

**An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.**

An IDOR hunt needs a parameter whose user-supplied value directly selects an object such as a picture, a comment, PII or a department, because that handle is what an attacker can repoint.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

- *Disproof:* No request parameter takes an object identifier from the client, so the object is chosen server-side and there is nothing for the tester to repoint.
- *Evidence:* high_confidence — [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/idor/idor.md); [portswigger.net](https://portswigger.net/web-security/access-control); [postgresql.org](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

**IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.**

Two multipliers make IDOR cheap to automate: nested references such as GET /invoices/{invoiceId}/items/{itemId} or /shops/{shopName}/revenue_data.json where you can hold one leg constant and vary the other, and enumerable keys where ids are sequential integers (CWE-639 lists sequential or easily-guessable ids as a manifestation). Note a GUID key does NOT remove the flaw: OWASP states access control checks remain essential even with complex identifiers, so treat unguessable ids as a hunt-priority reducer, never as a disproof.

- *Disproof:* All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/639.html)

**IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.**

IDOR/BOLA needs two things at once: an endpoint that accepts a user-controllable object id, and the absence of any check that the caller may access or modify the object that id resolves to.

HackTricks reference: IDOR (pentesting-web/idor.md)

- *Disproof:* An endpoint that accepts an attacker-supplied object id but still refuses cross-account access with 403 or 404 because it verifies the caller's ownership refutes the missing-authorization half of the claim.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/access-control/idor); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.**

Take a legitimate request as user A, record status/length/body hash, then replay the exact request in Repeater with the id replaced by an id from account B. OWASP notes the server response is usually enough to tell whether the request succeeded. Diff on more than status: compare Content-Length, JSON keys, presence of other-user PII (email, address, last4), and any owner_id/user_id echoed back. A 200 whose body length matches A's template but contains B's identifiers is a confirmed BOLA, not just an enumeration hint.

- *Disproof:* The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control)

**Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.**

If a list endpoint returns ids 1,2,4 you have a delisted record at 3 and can query it directly to recover non-listed state. Also harvest every identifier echoed in responses: owner_id, user_id, tenant_id, parent_id, invoice_id, avatar object keys. Those values are your wordlist for the substitution sweep. WSTG's GraphQL case shows the same shape: query the auth/resource set, extract foreign ids and tokens, then act as that principal.

- *Disproof:* Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/graphql); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An insecure direct object reference is proven by requesting an identical endpoint under another user's identifier and receiving that user's record instead of a 403/404.**

In practice on HTB this shows up as: The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as `User1`. However, with these details at hand, we can try repeating the same API call while logged in as `User2` to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the API call but has no access control on the back-end to compare the caller's session with the data being called.
<u>Mass IDOR Enumeration</u>:
We can try manually accessing other employee documents with `uid=3`, `uid=4`, and so on. However, manually accessing files is not efficient in a real work environment with hundreds or thousands of employees. So, we can either use a tool like `Burp Intruder` or `ZAP Fuzzer` to retrieve all files or write a small bash script to download all files.

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Web Application Attacks.md (3660 words, classified web).

- *Disproof:* Refuted when the server enforces an ownership check on the object identifier and returns 403/404 for a foreign object, which is the correct behaviour.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/639.html); [portswigger.net](https://portswigger.net/web-security/access-control/idor); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Web%20Application%20Attacks.md)

**The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.**

Baseline: GET /api/v1/customers/4471 with user A's Authorization: Bearer <jwt>. Then in Repeater change only the id, keeping method, headers, cookie and CSRF token fixed. Repeat across carriers for the same object: GET /customer_account?customer_number=132355, POST body {"invoiceId": 8830}, header X-Account-Id: 99. OWASP's own scenario is exactly this - take the shop-name list from one endpoint and substitute each name into /shops/{shopName}/revenue_data.json. Fixing everything except the key isolates authorization from every other variable.

- *Disproof:* Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control/idor)

**The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.**

The IDOR test is to modify the value of the parameter that points directly at an object and observe whether authorization is still enforced for the newly referenced object.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

- *Disproof:* Requesting another user's object id with the same session returns an authorization error and no data belonging to the other account.
- *Evidence:* high_confidence — [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/idor/idor.md); [portswigger.net](https://portswigger.net/web-security/access-control); [postgresql.org](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

**Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.**

Object ids that are GUIDs or so-called encrypted values must still be tested, because obscuring the object id is not an ownership check.

HackTricks reference: idor (https://kathan19.gitbook.io/howtohunt/idor/idor.md)

- *Disproof:* Two accounts swapping or altering opaque object ids never see each other's object, showing the authorization decision is enforced on something other than the id value.
- *Evidence:* high_confidence — [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/idor/idor.md); [portswigger.net](https://portswigger.net/web-security/access-control); [postgresql.org](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

**IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.**

IDOR coverage comes from pairing a forced-browse / auth-matrix pass that maps which roles may reach each endpoint with bulk sweeps of collected object ids, rather than probing one identifier at a time by hand.

HackTricks reference: IDOR (pentesting-web/idor.md)

- *Disproof:* A hunt that only issues single-id probes, or that never maps roles to endpoints, refutes this pairing as the thing that actually produces IDOR coverage.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/access-control/idor); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/idor.md)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.**

Register User A and User B, both low-privilege and in the same role. As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount). Record B's object id. Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200. OWASP prescribes exactly this A/B method and requires it across read, create, update, delete, export and admin actions. Attach full request/response pairs for both accounts.

- *Disproof:* As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/access-control/idor); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/)

**Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.**

As B, capture a mutable field on B's object (note title, shipping address, workflow state, visibility flag). As A, issue the write against B's id: PATCH /invoices/8830 {"status":"approved"}, or the GraphQL mutation deleteReports(reportKeys:["<B_DOCUMENT_ID>"]). Do not stop at a 200 - log back in as B in a clean browser and screenshot the mutated field, or confirm via an audit-log/read API. Write IDOR escalates severity because it turns a read bug into integrity loss and deletion.

- *Disproof:* The mutation returns 403/404 and B's object is byte-for-byte unchanged when re-read by B, or B's session shows a reverted/rolled-back state.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/639.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.**

Two frequent rejections. (1) Public-by-design: catalogue SKUs, published blog posts, delisted-but-public product rows, shared team boards and public invoice PDFs are readable by any authenticated user - confirm with the app's own UI that no privacy setting exists, and that OWASP's guidance to expose only fields the requester may read is already met. (2) Own-tenant: on multi-tenant SaaS you and the other user may share org_id; verify the ownership field (owner_id, tenant_id, org_id) in the returned payload actually differs before reporting.

- *Disproof:* The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control/idor)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**When object scoping is delegated to PostgreSQL row-level security, the policy is not the control if the connecting role is a superuser, has BYPASSRLS, or is the table owner - each of those silently ignores every policy on the table.**

This is the strongest architectural bypass in object-level authorization and it is invisible from HTTP behaviour alone, because it shows up as 'the data is right' in every test. PostgreSQL states it plainly: superusers and roles with the BYPASSRLS attribute always bypass the row security system, table owners normally bypass it too, and the owner can opt in with FORCE ROW LEVEL SECURITY. Policy expressions run with the privileges of the user running the query, which adds the second-order case: a policy that calls a security-definer function can read data the calling user could not. When you are assessing an application that relies on the database for tenant isolation, the questions are therefore about the connection role, not about the policy text. Reachability of a privileged role - a migration account reused at runtime, an admin tooling endpoint that runs under the same credentials, a superuser connection string in a config file or an SSRF-reachable internal service - converts a 'protected' table into a fully readable one.

- *Disproof:* The claim is false if the application connects as an unprivileged role with no BYPASSRLS attribute and does not own the table, in which case the policy is genuinely the effective control and every query is filtered by it. It is also false if FORCE ROW LEVEL SECURITY is set on the table, which pulls the owner back under the policy. And it is not by itself a remotely exploitable IDOR: the bypass requires the attacker to be able to make the server issue queries under the privileged role, which is an additional condition - a role configuration weakness rather than a broken object check. Table-level whole-table operations such as TRUNCATE and REFERENCES are also outside policy scope, but that is a different capability from reading another tenant's row.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/access-control/idor); [postgresql.org](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

**The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.**

Three bypasses. (1) Check-after-use: the handler reads and returns the row first, verifies ownership after, so the body leaks before the check throws - a 200 with complete data and an authorization error in the tail. (2) Unchecked method: only POST is gated at the gateway; PATCH/PUT/DELETE reach the handler. (3) Mass assignment: POST /api/host/approve_booking {"approved":true} becomes {"approved":true,"owner_id":4471}.

- *Disproof:* The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**IDOR chains to full account takeover when the readable object holds credentials, and to vertical privilege escalation when the writable object holds authority.**

Read-chain: an IDOR on a static transcript or export (GET /static/12144.txt) yields another user's credentials, which is immediate ATO. API-chain: an IDOR on a password-reset, email-change, session or recovery-record endpoint yields a reset token for someone else, then ATO. Write-chain: an IDOR that lets you set owner_id, role, is_admin or team_id on your own record converts horizontal access into vertical privilege escalation - CWE-639 calls out exactly the case where the user-controlled key is an admin flag. Report the chain, not just the swap.

- *Disproof:* The exposed object contains no credential, token, session or role-bearing field, and no writable endpoint accepts an ownership or privilege field from the client.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/639.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/); [portswigger.net](https://portswigger.net/web-security/access-control/idor)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**Frame IDOR impact as enumerated cross-tenant records per account class and per operation, and note OWASP rates it easy to exploit, widespread, and easy to detect.**

OWASP scores API1:2023 Exploitability Easy, Prevalence Widespread, Detectability Easy, Technical Moderate - state that so the triager sees the baseline. Then quantify only what you showed: "authenticated user read private invoices of one of two test tenants; sequential id space implies ~N records per tenant; write variant permitted status change and delete." Business impact follows the data class. Never claim bulk extraction you did not perform.

- *Disproof:* Only your own objects were ever readable/writable, no other account's data was ever returned, and no quantitative scope can be supported beyond a single test record.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/639.html); [owasp.org](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
