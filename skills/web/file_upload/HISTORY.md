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

## 2026-10-04 00:43 — 192 diff lines
- items: 32 (supported 22), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -20,121 +20,106 @@
 
 ## Techniques (what to change)
 
-- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. _(unverified)_
+- A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
+- An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
+- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. _(unverified)_
+- For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, java.io.FilePermission in the Java SecurityManager allows the software to spe".
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+- That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
+- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, java.io.FilePermission in the Java SecurityManager allows the software to spe".
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- The product allows the upload or transfer of dangerous file types that are automatically processed within its environment. _(unverified)_
+- The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product allows the upload or transfer of dangerous file types that are automatically p".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- This can give attackers enough room to bypass the intended validation. _(unverified)_
+- This can give attackers enough room to bypass the intended validation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. _(unverified)_
+- This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may effectively restrict which files can be accessed in a particular directory or whi".
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
-  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.
-  - **Disproof:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.
-  - **Disproof:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
-  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
-- Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.
+- Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the upload is stored outside any served or executable path, or the content is rewritten to an inert type, so no interpreter ever executes the uploaded bytes.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://portswigger.net/web-security/file-upload> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31c.%20File%20Upload%20Attacks/File%20Upload%20Attacks.md>
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.bypass.an_extension_allowlist_is_defeated_by_server_side_parsing_of_the_upload) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output.
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
+- To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.
+  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
+- To decide this case, observe: Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.prove_retrieval_of_the_stored_file_over_http) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
+- To decide this case, observe: Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.fetch_stored_object_as_interpreter_would) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
-- To decide this case, observe: Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.prove_retrieval_of_the_stored_file_over_http) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.accepting_an_upload_and_storing_it_is_not_itself_a_vulnerability) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.a_client_supplied_content_type_header_is_not_type_validation) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.
-  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
 
 ## Validation bar (how to prove it)
 
-- An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.
+- An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
-- The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.
+- The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
 
 ## False-positive rules (when to reject it)
 
-- Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes.
+- An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+- The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.
+  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
+- Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-declared value, since the attacker controls that field directly and the same request can be replayed with any declared type.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.
-  - **Disproof:** It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
-- Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension.
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 32 (supported 22), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -132,10 +132,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Upload with a double extension, a trailing dot or space, and a MIME/header mismatch; compare against the baseline accepted type.
+2. Confirm the stored file is served back with an executable content type from a reachable path, and check whether it renders or executes.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 32 (supported 22), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -144,6 +144,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/file_upload/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 48 diff lines
- items: 32 (supported 28), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 32 items, 22 supported, 6 FP rules, 1 chains
+> evidence: 32 items, 28 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 The server accepts an upload without constraining type, name, location or interpretation.
@@ -26,26 +26,26 @@
 - An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.  _(merged 1 duplicate row(s))_
   - **Disproof:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
+- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Files are scanned in memory at upload time, allowing applications to make accept”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, java.io.FilePermission in the Java SecurityManager allows the software to spe".
+- For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, java.io.FilePermission in the Java SecurityManager allows the softw”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
+- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The effectiveness of this mitigation depends on the prevention capabilities of t”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product allows the upload or transfer of dangerous file types that are automatically p".
+- The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The product allows the upload or transfer of dangerous file types that are autom”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - This can give attackers enough room to bypass the intended validation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may effectively restrict which files can be accessed in a particular directory or whi".
+- This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This may effectively restrict which files can be accessed in a particular direct”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the upload is stored outside any served or executable path, or the content is rewritten to an inert type, so no interpreter ever executes the uploaded bytes.
```

## 2026-10-28 14:45 — 63 diff lines
- items: 23 (supported 23), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 32 items, 28 supported, 6 FP rules, 1 chains
+> evidence: 23 items, 23 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 The server accepts an upload without constraining type, name, location or interpretation.
@@ -26,24 +26,18 @@
 - An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.  _(merged 1 duplicate row(s))_
   - **Disproof:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
-- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.  _(merged 2 duplicate row(s))_
+- Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Files are scanned in memory at upload time, allowing applications to make accept”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, java.io.FilePermission in the Java SecurityManager allows the softw”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
-  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The effectiveness of this mitigation depends on the prevention capabilities of t”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The product allows the upload or transfer of dangerous file types that are autom”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
-- This can give attackers enough room to bypass the intended validation.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
-  - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
 - This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This may effectively restrict which files can be accessed in a particular direct”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
@@ -53,12 +47,6 @@
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.bypass.an_extension_allowlist_is_defeated_by_server_side_parsing_of_the_upload) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
 - To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
@@ -104,10 +92,10 @@
 
 ## Impact framing
 
-- Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.  _(merged 2 duplicate row(s))_ _(unverified)_
+- Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.  _(merged 1 duplicate row(s))_
   - **Disproof:** The accepted file is renamed, stored outside any executable path and served back as inert content with no execution on the server.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
-- End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.  _(merged 2 duplicate row(s))_ _(unverified)_
+- End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.  _(merged 1 duplicate row(s))_
   - **Disproof:** Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
 
```

## 2026-10-28 21:18 — 51 diff lines
- items: 31 (supported 30), FP rules 6, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 23 items, 23 supported, 6 FP rules, 1 chains
+> evidence: 31 items, 30 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 The server accepts an upload without constraining type, name, location or interpretation.
@@ -98,18 +98,39 @@
 - End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.  _(merged 1 duplicate row(s))_
   - **Disproof:** Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
+- The application accepts and publicly serves an uploaded SVG image that contains inline scriptable content (e.g., <script>alert(1)</script>, <image xlink:href=\"javascript:alert(1)\">, <iframe srcdoc>, or a data URI); because the file is served from the same origin as the upload endpoint, any user who renders the SVG executes the script in the application's origin - stored XSS with session theft, CSRF, or defacement as the impact.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the upload endpoint strips/escapes <script> and event handlers, or stores only sanitized SVG (no script-capable elements), or if the file is served with Content-Disposition: attachment / X-Content-Type-Options: nosniff (preventing MIME sniffing and script execution), or if it is hosted on a separate origin (e.g., a CDN on a different domain), the script never executes.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> · <https://portswigger.net/web-security/file-upload> · <https://secra.es/en/blog/file-upload-vulnerability-webshell-rce>
+- The application trusts the client-supplied filename field and does not validate the save path; an attacker uses '../' sequences in the filename (CWE-23 relative path traversal) to write outside the intended upload directory - overwriting an existing, high-value file such as .htaccess, a web server config, a library the application loads, or a script in the webroot - thereby changing server behavior or achieving code execution from a previously innocuous file.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the filename is sanitized server-side (basename extraction, UUID rename, path construction with a fixed upload root), if the save is jailed in a chroot or directory sandbox, or if the OS sandbox (open_basedir, container seccomp, permissions) prevents writes outside the target directory, the traversal is blocked.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> · <https://portswigger.net/web-security/file-upload>
 
 ## Defence bypasses
 
 - An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
+- The application blocks dangerous extensions with a blacklist, but the check is bypassable via parsing discrepancies: null-byte truncation (.php%00.jpg), double extensions (.php.jpg), case manipulation (.pHp), trailing characters (.php.), URL-encoded dots (%2Ephp), semicolons before the extension (.asp;.jpg), multibyte unicode dots, and non-recursive stripping of the prohibited string (exploit.p.phphp).  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If extension resolution happens after full percent-decoding and Unicode normalization on both sides (no decoding discrepancy), if null-byte handling is identical across validation and execution, if the filter applies the blacklisting recursively (p.phphp -> phphp -> stripped), and if both sides treat extension names case-sensitively, the payload is inert.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> · <https://portswigger.net/web-security/file-upload> · <https://zetsu.ninja/book/portswigger/file-upload/>
+- The application validates an uploaded file only against the input-specific Content-Type header, which the client controls and which the server implicitly trusts; an attacker sets Content-Type: image/jpeg while the body is a PHP webshell, the server accepts the file, stores it, and serves/executes it as a web shell.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the server re-derives the MIME type from the file's magic bytes (not the header), or re-encodes/decodes the file before storage, the spoofed header is ignored and the payload is blocked; if the upload directory is not executable (scripts served as text/plain) or is outside the webroot, the stored webshell is inert.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> · <https://portswigger.net/web-security/file-upload> · <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass>
+- The application validates only the leading magic bytes of the uploaded file (a fixed prefix such as GIF89a or FF D8 FF E0) and fails to verify the complete signature or the remainder of the content; an attacker uploads a polyglot whose header is a valid image signature followed by the malicious script appended after the signature, so the partial check passes and the file is executed as code.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the file is decoded and re-encoded (ImageMagick convert, etc.) before execution - which discards the appended payload - or if the check requires a full/multi-byte signature match plus content-type agreement, or if the stored file is never served as an executable (served as text/plain / attachment), the appended script never runs.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> · <https://portswigger.net/web-security/file-upload> · <https://portswigger.net/kb/issues/00500980_file-upload-functionality>
 
 ## Chaining opportunities
 
 - An upload endpoint that neither canonicalises the client filename nor constrains the extension chains into path traversal and then interpreter-reachable execution, so a single weak upload control converts into code execution without any second primitive.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the server canonicalises the multipart filename to a basename before touching the filesystem, or if the storage directory lies outside every interpreter-mapped document root; either control alone breaks the traversal-to-execution join even when the other is missing.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
+- Chain link: a single unrestricted file upload flaw escalates to full remote code execution. The attacker slips a webshell (PHP/ASP/JSP) past the flawed filter and stores it in a reachable, executable location; a follow-up HTTP request executes the script, returning command output and granting the attacker full control of the server.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the uploaded directory does not execute scripts (served as text/plain), is outside the webroot and only reachable via an ID->filename handler, the server rewrites filenames server-side so the original name is never requested, the file is stored only in a temp/untrusted location and never served, or a CDR/WAF/CDN strips the webshell payload - the chain fails at the execution step.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://portswigger.net/web-security/file-upload> · <https://secra.es/en/blog/file-upload-vulnerability-webshell-rce>
+- Chain link: the attacker uploads their own web-server configuration file (.htaccess on Apache, web.config on IIS) into the user-uploaded directory, forcing the server to map a harmless whitelisted extension to an executable MIME type. Even with a strict extension whitelist, subsequent uploads with the whitelisted extension are executed as code.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the web server has per-directory configuration overrides disabled (AllowOverride None on Apache; locked IIS handler mapping / disabled web.config inheritance), the uploaded config is ignored; if uploads are stored outside the webroot or the directory has script execution disabled, the reordering of the handler is harmless.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> · <https://portswigger.net/kb/issues/00500980_file-upload-functionality> · <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass>
 
 ## Rejected before you report
 
```

## 2026-10-31 06:41 — 60 diff lines
- items: 31 (supported 24), FP rules 4, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 434 · OWASP A04:2021
-> evidence: 31 items, 30 supported, 6 FP rules, 1 chains
+> evidence: 31 items, 24 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 The server accepts an upload without constraining type, name, location or interpretation.
@@ -23,7 +23,7 @@
 - A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
-- An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.  _(merged 1 duplicate row(s))_
+- An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
 - Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.  _(merged 1 duplicate row(s))_
@@ -47,10 +47,10 @@
 
 ## Tests
 
-- To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
-- To decide this case, observe: Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.prove_retrieval_of_the_stored_file_over_http) states the full boundary.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
 - To decide this case, observe: Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output.  _(merged 1 duplicate row(s))_
@@ -62,7 +62,7 @@
 - An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
-- The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.  _(merged 1 duplicate row(s))_
+- The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
 
@@ -71,7 +71,7 @@
 - An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
-- The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.  _(merged 1 duplicate row(s))_
+- The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://nginx.org/en/docs/http/ngx_http_core_module.html>
 - Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes.  _(merged 1 duplicate row(s))_
@@ -80,7 +80,7 @@
 - Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.
   - Sources: <https://docs.python.org/3/library/tempfile.html> · <https://www.php.net/manual/en/features.file-upload.php>
-- When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.  _(merged 1 duplicate row(s))_
+- When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.
   - Sources: <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 31 (supported 24), FP rules 4, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -152,7 +152,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/web/file_upload/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
+Full class document: `skills/web/file_upload/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id file_upload`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 31 (supported 24), FP rules 4, chains 1, state mature

```diff
--- file_upload@current
+++ file_upload@new
@@ -5,7 +5,8 @@
 
 # Unrestricted File Upload — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
