# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 3 (supported 3), FP rules 1, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 3 (supported 3), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- file_upload@current
+++ file_upload@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 434 · OWASP A04:2021
 > evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 The server accepts an upload without constraining type, name, location or interpretation.
 
```

## 2026-10-02 11:03 — 46 diff lines
- items: 6 (supported 6), FP rules 3, chains 1, state researching
- still missing: items

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 6 items, 6 supported, 3 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 The server accepts an upload without constraining type, name, location or interpretation.
 
@@ -27,11 +27,32 @@
   - **Disproof:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
   - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 
+## Validation bar (how to prove it)
+
+- An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.
+  - **Disproof:** Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+
 ## False-positive rules (when to reject it)
 
 - When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.
   - **Disproof:** If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.
   - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+- An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.
+  - **Disproof:** Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+
+## Chaining opportunities
+
+- An upload endpoint that neither canonicalises the client filename nor constrains the extension chains into path traversal and then interpreter-reachable execution, so a single weak upload control converts into code execution without any second primitive.
+  - **Disproof:** Refuted if the server canonicalises the multipart filename to a basename before touching the filesystem, or if the storage directory lies outside every interpreter-mapped document root; either control alone breaks the traversal-to-execution join even when the other is missing.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+
+## Rejected before you report
+
+- **An upload endpoint that accepts a .php file and returns 200 is an unrestricted file upload vulnerability.**
+  - Killed by: The direct path returned 404 and the handler served the bytes as application/octet-stream from outside the document root; the object is stored outside the webroot behind an application handler and no interpreter ever evaluates it, so CWE-434's execution precondition is unmet.
+  - Rule: Acceptance is not execution. Confirm unrestricted file upload by retrieving the stored object at a path an interpreter claims and observing it parsed or executed; storage outside the webroot behind an application handler satisfies OWASP guidance even when the extension is accepted.
 
 ---
 Full class document: `classes/file_upload.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 6 (supported 6), FP rules 3, chains 1, state researching
- still missing: items

```diff
--- file_upload@current
+++ file_upload@new
@@ -55,4 +55,4 @@
   - Rule: Acceptance is not execution. Confirm unrestricted file upload by retrieving the stored object at a path an interpreter claims and observing it parsed or executed; storage outside the webroot behind an application handler satisfies OWASP guidance even when the extension is accepted.
 
 ---
-Full class document: `classes/file_upload.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
+Full class document: `skills/Web/file_upload/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
```
