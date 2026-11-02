# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-01 22:49 — 1 diff lines
- items: 10 (supported 10), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain, skill

```diff
(initial generation, 2026-10-01)
```

## 2026-10-01 22:49 — 17 diff lines
- items: 10 (supported 10), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain, skill

```diff
--- idor@current
+++ idor@new
@@ -9,13 +9,9 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `api` · CWE CWE-639 · OWASP API1:2023
+> surface `api` · CWE — · OWASP —
 > evidence: 10 items, 10 supported, 0 FP rules, 0 chains
 > maturity: **researching** — missing: methodology, items, fp_rules, chain, skill
-
-A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
-
-**Also called:** broken object level authorization, bola, insecure direct object reference, object level authorization failure, horizontal privilege escalation via id
 
 
 ## Prerequisites (do not start without these)
```

## 2026-10-01 22:50 — 30 diff lines
- items: 10 (supported 10), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain, skill

```diff
--- idor@current
+++ idor@new
@@ -25,21 +25,21 @@
 
 ## Recon signals (where to look)
 
+- Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.
+  - **Disproof:** Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.
+  - Sources: <https://portswigger.net/web-security/graphql> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
 - A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.
   - **Disproof:** The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control>
-- Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.
-  - **Disproof:** Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.
-  - Sources: <https://portswigger.net/web-security/graphql> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
 
 ## Techniques (what to change)
 
+- Nested references and URL-matching discrepancies (trailing slash, extension suffix, case) let a validated parent path reach an unvalidated child object.
+  - **Disproof:** Both legs of every nested path are independently authorized against the session owner, and trailing-slash, extension-suffix and case variants are rejected with 404 rather than routed.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
 - The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.
   - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
-- Nested references and URL-matching discrepancies (trailing slash, extension suffix, case) let a validated parent path reach an unvalidated child object.
-  - **Disproof:** Both legs of every nested path are independently authorized against the session owner, and trailing-slash, extension-suffix and case variants are rejected with 404 rather than routed.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-01 22:52 — 25 diff lines
- items: 10 (supported 10), FP rules 1, chains 1, state researching
- still missing: methodology, items, fp_rules, skill

```diff
--- idor@current
+++ idor@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE — · OWASP —
-> evidence: 10 items, 10 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain, skill
+> evidence: 10 items, 10 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: methodology, items, fp_rules, skill
 
 
 ## Prerequisites (do not start without these)
@@ -62,5 +62,11 @@
   - **Disproof:** The exposed object contains no credential, token, session or role-bearing field, and no writable endpoint accepts an ownership or privilege field from the client.
   - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
 
+## Rejected before you report
+
+- **GET /api/invoice/{id} returns another user's invoice data**
+  - Killed by: Both accounts received byte-identical bodies; the id is resolved within the caller's tenant server-side, so no other tenant's record was reachable
+  - Rule: A 200 with data is not a finding until the same identifier is shown to resolve differently for a second identity; compare bodies, not status codes
+
 ---
 Full class document: `classes/idor.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
```

## 2026-10-01 22:55 — 18 diff lines
- items: 10 (supported 10), FP rules 1, chains 1, state researching
- still missing: methodology, items, fp_rules

```diff
--- idor@current
+++ idor@new
@@ -9,9 +9,13 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `api` · CWE — · OWASP —
+> surface `api` · CWE CWE-639 · OWASP API1:2023
 > evidence: 10 items, 10 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, skill
+> maturity: **researching** — missing: methodology, items, fp_rules
+
+A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
+
+**Also called:** broken object level authorization, bola, insecure direct object reference, object level authorization failure, horizontal privilege escalation via id
 
 
 ## Prerequisites (do not start without these)
```

## 2026-10-01 23:20 — 45 diff lines
- items: 14 (supported 14), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- idor@current
+++ idor@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 10 items, 10 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, items, fp_rules
+> evidence: 14 items, 14 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: methodology, fp_rules
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
 
@@ -38,6 +38,12 @@
 
 ## Techniques (what to change)
 
+- Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.
+  - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+- Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.
+  - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://docs.github.com/en/graphql/guides/using-global-node-ids>
 - Nested references and URL-matching discrepancies (trailing slash, extension suffix, case) let a validated parent path reach an unvalidated child object.
   - **Disproof:** Both legs of every nested path are independently authorized against the session owner, and trailing-slash, extension-suffix and case variants are rejected with 404 rather than routed.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
@@ -60,6 +66,18 @@
   - **Disproof:** The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
 
+## Impact framing
+
+- Frame IDOR impact as enumerated cross-tenant records per account class and per operation, and note OWASP rates it easy to exploit, widespread, and easy to detect.
+  - **Disproof:** Only your own objects were ever readable/writable, no other account's data was ever returned, and no quantitative scope can be supported beyond a single test record.
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
+
+## Defence bypasses
+
+- The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.
+  - **Disproof:** The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.
+  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
+
 ## Chaining opportunities
 
 - IDOR chains to full account takeover when the readable object holds credentials, and to vertical privilege escalation when the writable object holds authority.
```

## 2026-10-01 23:21 — 21 diff lines
- items: 13 (supported 13), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 14 items, 14 supported, 1 FP rules, 1 chains
+> evidence: 13 items, 13 supported, 1 FP rules, 1 chains
 > maturity: **researching** — missing: methodology, fp_rules
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -44,9 +44,6 @@
 - Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.
   - **Disproof:** Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://docs.github.com/en/graphql/guides/using-global-node-ids>
-- Nested references and URL-matching discrepancies (trailing slash, extension suffix, case) let a validated parent path reach an unvalidated child object.
-  - **Disproof:** Both legs of every nested path are independently authorized against the session owner, and trailing-slash, extension-suffix and case variants are rejected with 404 rather than routed.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
 - The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.
   - **Disproof:** Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
```

## 2026-10-01 23:46 — 11 diff lines
- items: 13 (supported 13), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- idor@current
+++ idor@new
@@ -11,7 +11,7 @@
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
 > evidence: 13 items, 13 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, fp_rules
+> maturity: **researching** — missing: fp_rules
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
 
```

## 2026-10-02 01:36 — 11 diff lines
- items: 13 (supported 13), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- idor@current
+++ idor@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
 > evidence: 13 items, 13 supported, 1 FP rules, 1 chains
```

## 2026-10-02 10:30 — 45 diff lines
- items: 13 (supported 11), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 13 items, 13 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: fp_rules
+> evidence: 13 items, 11 supported, 3 FP rules, 2 chains
+> maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
 
@@ -20,7 +20,7 @@
 
 ## Prerequisites (do not start without these)
 
-- IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.
+- IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body. _(unverified)_
   - **Disproof:** Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.
   - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
 - IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.
@@ -50,7 +50,7 @@
 
 ## Validation bar (how to prove it)
 
-- Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.
+- Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated. _(unverified)_
   - **Disproof:** As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
 - Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.
@@ -86,6 +86,13 @@
 - **GET /api/invoice/{id} returns another user's invoice data**
   - Killed by: Both accounts received byte-identical bodies; the id is resolved within the caller's tenant server-side, so no other tenant's record was reachable
   - Rule: A 200 with data is not a finding until the same identifier is shown to resolve differently for a second identity; compare bodies, not status codes
+- **Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.**
+  - Killed by: The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
+  - Rule: Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.
+
+## Chains to
+
+- `jwt` (3 shared chain(s))
 
 ---
 Full class document: `classes/idor.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
```

## 2026-10-02 13:38 — 27 diff lines
- items: 14 (supported 12), FP rules 3, chains 2, state mature

```diff
--- idor@current
+++ idor@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-639 · OWASP API1:2023
-> evidence: 13 items, 11 supported, 3 FP rules, 2 chains
+> evidence: 14 items, 12 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.
@@ -38,6 +38,9 @@
 
 ## Techniques (what to change)
 
+- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The system's authorization functionality does not prevent one user from gaining access to ".
+  - Sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
 - Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.
   - **Disproof:** Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
@@ -95,4 +98,4 @@
 - `jwt` (3 shared chain(s))
 
 ---
-Full class document: `classes/idor.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
+Full class document: `skills/Web/idor/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id idor`
```
