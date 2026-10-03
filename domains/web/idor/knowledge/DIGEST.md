# IDOR / BOLA (Object-Level Authorization)

> surface: `api` · CWE: CWE-639 · OWASP: API1:2023
> maturity: **mature** — 14 items, 14 supported, 3 FP rules, 2 chains

A server fails to verify that the authenticated caller is entitled to the specific object identified by the request, so one user reaches another's data.

**Aliases:** broken object level authorization, bola, insecure direct object reference, object level authorization failure, horizontal privilege escalation via id

## Prerequisite

- **IDOR/BOLA is only possible where a client-supplied identifier selects the object the server acts on, in the path, query string, header or body.**  
  `high_confidence` · score 0.885 · disproved by: Every request either carries no object identifier at all, or the identifier is server-generated/signed and cannot be altered without invalidating the request.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor>
- **IDOR is exploitable at scale when object references are nested (child object under a parent path) or are sequential/guessable values.**  
  `high_confidence` · score 0.814 · disproved by: All references are high-entropy and non-derivable, or every nested route validates the parent-child relationship against the session owner before acting.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>

## Signal

- **A response that differs materially when you substitute another user's object id (200 + their data instead of 403/404) is the primary recon signal for BOLA.**  
  `high_confidence` · score 0.924 · disproved by: The substituted-id response is byte-identical in status and body to the own-object response, or returns 403/404 with no B-owned fields anywhere in the payload.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control>
- **Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.**  
  `high_confidence` · score 0.893 · disproved by: Every id returned is an opaque non-sequential token with no gaps to infer, and no response contains any foreign owner or tenant identifier.
  sources: <https://portswigger.net/web-security/graphql> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>

## Technique

- **The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header - with no other change.**  
  `high_confidence` · score 0.924 · disproved by: Every carrier version of the request returns 403/404 or a B-owned payload identical in length and content to the baseline denial.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>
- **Platform or gateway authorization keyed on method and content-type can be sidestepped with a verb change, X-HTTP-Method-Override, or a x-www-form-urlencoded replay.**  
  `high_confidence` · score 0.839 · disproved by: Unapproved verbs and overridden methods return 405 Method Not Allowed, and the form-encoded replay is rejected with 415 Unsupported Media Type.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>
- **Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.**  
  `high_confidence` · score 0.8115 · disproved by: Both legs of every nested path are independently authorized, routing variants 404, and node(id:)/nodes(ids:) is absent from the schema or enforces ownership.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html> · <https://docs.github.com/en/graphql/guides/using-global-node-ids>
- **The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The system's authorization functionality does not prevent one user from gaining access to ".
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>

## Validation

- **Cross-tenant read is only proven when user A retrieves an object created and exclusively owned by user B, with the two accounts fully separated.**  
  `high_confidence` · score 0.9065 · disproved by: As A the request returns 403/404 or an empty record, and the canary string never appears in any A-visible response; or B's object turns out to be shared/public by design.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control/idor> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/>
- **Cross-tenant write is proven only when user A's mutation changes state on B's object and B observes the change in their own authenticated session.**  
  `high_confidence` · score 0.806 · disproved by: The mutation returns 403/404 and B's object is byte-for-byte unchanged when re-read by B, or B's session shows a reverted/rolled-back state.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>

## Fp Rule

- **Reject the finding when the object is intentionally public/shared, or when the returned record actually belongs to the reporter's own tenant or account.**  
  `high_confidence` · score 0.8965 · disproved by: The payload's owner/tenant/organisation identifier equals the reporter's session identity or their org, or the resource is documented/public in the product UI with no sharing control.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://portswigger.net/web-security/access-control/idor>

## Impact

- **Frame IDOR impact as enumerated cross-tenant records per account class and per operation, and note OWASP rates it easy to exploit, widespread, and easy to detect.**  
  `high_confidence` · score 0.8575 · disproved by: Only your own objects were ever readable/writable, no other account's data was ever returned, and no quantitative scope can be supported beyond a single test record.
  sources: <https://cwe.mitre.org/data/definitions/639.html> · <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>

## Bypass

- **The most common bypass is a check that runs after the object is already used, or a path where method/owner fields are never validated at all.**  
  `high_confidence` · score 0.83 · disproved by: The authorization check executes before any read or mutation and short-circuits the response; non-listed methods return 405; and injected owner_id/role/price fields are ignored or explicitly rejected.
  sources: <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/access-control>

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
