# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 14 (supported 14), FP rules 3, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 14 (supported 14), FP rules 3, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -79,4 +79,4 @@
   - Rule: Acceptance is not execution. Confirm unrestricted file upload by retrieving the stored object at a path an interpreter claims and observing it parsed or executed; storage outside the webroot behind an application handler satisfies OWASP guidance even when the extension is accepted.
 
 ---
-Full class document: `domains/web/file_upload/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
+Full class document: `domains/web/file_upload/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
```

## 2026-10-02 19:37 — 111 diff lines
- items: 26 (supported 16), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 14 items, 14 supported, 3 FP rules, 1 chains
+> evidence: 26 items, 16 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 The server accepts an upload without constraining type, name, location or interpretation.
@@ -20,28 +20,28 @@
 
 ## Techniques (what to change)
 
-- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.
+- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.
+- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.
+- For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, java.io.FilePermission in the Java SecurityManager allows the software to spe".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.
+- The product allows the upload or transfer of dangerous file types that are automatically processed within its environment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product allows the upload or transfer of dangerous file types that are automatically p".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.
+- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- This can give attackers enough room to bypass the intended validation.
+- This can give attackers enough room to bypass the intended validation. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.
+- This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may effectively restrict which files can be accessed in a particular directory or whi".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.
+- That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.
@@ -51,20 +51,62 @@
   - **Disproof:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
   - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 
+## Tests
+
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.bypass.an_extension_allowlist_is_defeated_by_server_side_parsing_of_the_upload) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
+- To decide this case, observe: ype, and whether the body comes back as raw bytes or as interpreted output. The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type. That is the CWE-434 precondition satisfied, and it is especially true for extensions such as .asp a
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.fetch_stored_object_as_interpreter_would) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+- To decide this case, observe: e is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before t
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.prove_retrieval_of_the_stored_file_over_http) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside t
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.accepting_an_upload_and_storing_it_is_not_itself_a_vulnerability) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-decla _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.a_client_supplied_content_type_header_is_not_type_validation) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
+- To decide this case, observe: that name, so the finding caps at arbitrary file write with the server account's privileges. Escalate to code execution only when the writable set demonstrably includes a file the server itself parses or executes, such as init scripts or the server executable itself. State the privilege bound in the write-up, since a write as an unprivileged service account is a materially diff
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.
+  - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+
 ## Validation bar (how to prove it)
 
 - An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.
   - **Disproof:** Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+- The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.
+  - **Disproof:** If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
 
 ## False-positive rules (when to reject it)
 
+- Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes.
+  - **Disproof:** It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-declared value, since the attacker controls that field directly and the same request can be replayed with any declared type.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
+- The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.
+  - **Disproof:** It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
+- Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension.
+  - **Disproof:** It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
 - When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.
   - **Disproof:** If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.
   - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.
   - **Disproof:** Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+
+## Defence bypasses
+
+- An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another.
+  - **Disproof:** It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
 
 ## Chaining opportunities
 
```

## 2026-10-03 01:46 — 111 diff lines
- items: 32 (supported 22), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 26 items, 16 supported, 6 FP rules, 1 chains
+> evidence: 32 items, 22 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 The server accepts an upload without constraining type, name, location or interpretation.
@@ -25,7 +25,7 @@
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, java.io.FilePermission in the Java SecurityManager allows the software to spe".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
@@ -37,43 +37,46 @@
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - This can give attackers enough room to bypass the intended validation. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may effectively restrict which files can be accessed in a particular directory or whi".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.
   - **Disproof:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.
   - **Disproof:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
-  - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
+- Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.
+  - **Disproof:** Refuted when the upload is stored outside any served or executable path, or the content is rewritten to an inert type, so no interpreter ever executes the uploaded bytes.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://portswigger.net/web-security/file-upload> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31c.%20File%20Upload%20Attacks/File%20Upload%20Attacks.md>
 
 ## Tests
 
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.bypass.an_extension_allowlist_is_defeated_by_server_side_parsing_of_the_upload) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: ype, and whether the body comes back as raw bytes or as interpreted output. The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type. That is the CWE-434 precondition satisfied, and it is especially true for extensions such as .asp a
+- To decide this case, observe: Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.fetch_stored_object_as_interpreter_would) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
-- To decide this case, observe: e is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before t
+- To decide this case, observe: Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.prove_retrieval_of_the_stored_file_over_http) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside t
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.accepting_an_upload_and_storing_it_is_not_itself_a_vulnerability) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-decla _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.a_client_supplied_content_type_header_is_not_type_validation) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: that name, so the finding caps at arbitrary file write with the server account's privileges. Escalate to code execution only when the writable set demonstrably includes a file the server itself parses or executes, such as init scripts or the server executable itself. State the privilege bound in the write-up, since a write as an unprivileged service account is a materially diff
+- To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.
-  - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
 
 ## Validation bar (how to prove it)
 
@@ -97,10 +100,31 @@
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
 - When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.
   - **Disproof:** If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.
-  - Sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
 - An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.
   - **Disproof:** Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+
+## Evidence requirements
+
+- A convincing observation for this class is: The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (file_upload.validation.fetch_stored_object_as_interpreter_would) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+
+## Impact framing
+
+- End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data. _(unverified)_
+  - **Disproof:** Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
+- Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server. _(unverified)_
+  - **Disproof:** The accepted file is renamed, stored outside any executable path and served back as inert content with no execution on the server.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
+- End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.
+  - **Disproof:** Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
+- Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.
+  - **Disproof:** The accepted file is renamed, stored outside any executable path and served back as inert content with no execution on the server.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
 
 ## Defence bypasses
 
```
