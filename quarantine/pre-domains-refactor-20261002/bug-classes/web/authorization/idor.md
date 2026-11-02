# IDOR / BOLA (Object-Level Authorization)

## Definition

A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.

- **CWE:** CWE-639
- **OWASP:** API1:2023
- **Surface:** api
- **Aliases:** ["broken object level authorization", "bola", "insecure direct object reference", "object level authorization failure", "horizontal privilege escalation via id"]

Canonical home for `idor`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.**

Enumerate every identifier carrier in the app: path segments (GET /invoices/1043), query params (?invoice_id=1043 or ?customer_number=132355), JSON body fields ("documentId", "owner_id"), headers (X-Account-Id, X-Request-Id), hidden form fields (<input type="hidden" name="user_id" value="12345">) and cookies. If no client-controlled key reaches the data access path, there is no IDOR surface. Static paths with no key (GET /documents/annual-report.pdf) are still IDOR-prone because the filename itself acts as the reference.

*Disproof:* Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.

**IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.**

Two multipliers make IDOR cheap to automate: nested references such as GET /invoices/{invoiceId}/items/{itemId} or /shops/{shopName}/revenue_data.json where you can hold one leg constant and vary the other, and enumerable keys where ids are sequential integers (CWE-639 lists sequential or easily-guessable ids as a manifestation). Note a GUID key does NOT remove the flaw: OWASP states access control checks remain essential even with complex identifiers, so treat unguessable ids as a hunt-priority reducer, never as a disproof.

*Disproof:* All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.

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

## Exploitation

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

**Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.**

Register User A and User B, both low-privilege and in the same role. As B, create a distinctive object (a draft document titled IDOR_CANARY_B_<random>, a support ticket, an invoice for a unique amount). Record B's object id. Replay the request as A with that id and confirm the response body contains the canary string and B's identity fields, not merely a 200. OWASP prescribes exactly this A/B method and requires it across read, create, update, delete, export and admin actions. Attach full request/response pairs for both accounts.

*Disproof:* As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.

**Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.**

As B, capture a mutable field on B's object (note title, shipping address, workflow state, visibility flag). As A, issue the write against B's id: PATCH /invoices/8830 {"status":"approved"}, or the GraphQL mutation deleteReports(reportKeys:["<B_DOCUMENT_ID>"]). Do not stop at a 200 - log back in as B in a clean browser and screenshot the mutated field, or confirm via an audit-log/read API. Write IDOR escalates severity because it turns a read bug into integrity loss and deletion.

*Disproof:* The mutation returns 403/404 and B's object is byte-for-byte unchanged when re-read by B, or B's session shows a reverted/rolled-back state.

## Impact

**Frame IDOR impact as enumerated cross-tenant records per account class and per operation, and note OWASP rates it easy to exploit, widespread, and easy to detect.**

OWASP scores API1:2023 Exploitability Easy, Prevalence Widespread, Detectability Easy, Technical Moderate - state that so the triager sees the baseline. Then quantify only what you showed: "authenticated user read private invoices of one of two test tenants; sequential id space implies ~N records per tenant; write variant permitted status change and delete." Business impact follows the data class. Never claim bulk extraction you did not perform.

*Disproof:* Only your own objects were ever readable/writable, no other account's data was ever returned, and no quantitative scope can be supported beyond a single test record.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/639.html>
- **docs.github.com** (docs)
  - <https://docs.github.com/en/graphql/guides/using-global-node-ids>
- **owasp.org** (taxonomy)
  - <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
  - <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/access-control>
  - <https://portswigger.net/web-security/access-control/idor>
  - <https://portswigger.net/web-security/graphql>
- **wstg.owasp.org** (research)
  - <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
