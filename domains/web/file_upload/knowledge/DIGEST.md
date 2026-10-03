# Unrestricted File Upload

> surface: `web` · CWE: 434 · OWASP: A04:2021
> maturity: **mature** — 14 items, 14 supported, 3 FP rules, 1 chains

The server accepts an upload without constraining type, name, location or interpretation.

**Aliases:** file upload, unrestricted upload, web shell upload

## Technique

- **An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.**  
  `high_confidence` · score 0.948 · disproved by: The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
- **A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.**  
  `high_confidence` · score 0.8465 · disproved by: If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
  sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
- **Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Files are scanned in memory at upload time, allowing applications to make accept or reject".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
- **The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, java.io.FilePermission in the Java SecurityManager allows the software to spe".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product allows the upload or transfer of dangerous file types that are automatically p".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **This can give attackers enough room to bypass the intended validation.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may effectively restrict which files can be accessed in a particular directory or whi".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>

## Validation

- **An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.**  
  `high_confidence` · score 0.96 · disproved by: Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>

## Fp Rule

- **An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.**  
  `high_confidence` · score 0.869 · disproved by: Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
- **When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.**  
  `high_confidence` · score 0.783 · disproved by: If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.
  sources: <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/> · <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>

## Chain Link

- **An upload endpoint that neither canonicalises the client filename nor constrains the extension chains into path traversal and then interpreter-reachable execution, so a single weak upload control converts into code execution without any second primitive.**  
  `high_confidence` · score 0.8775 · disproved by: Refuted if the server canonicalises the multipart filename to a basename before touching the filesystem, or if the storage directory lies outside every interpreter-mapped document root; either control alone breaks the traversal-to-execution join even when the other is missing.
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>

## False-positive rules

- **Hypothesis:** An upload endpoint that accepts a .php file and returns 200 is an unrestricted file upload vulnerability.
  - **Invalidated by:** The direct path returned 404 and the handler served the bytes as application/octet-stream from outside the document root; the object is stored outside the webroot behind an application handler and no interpreter ever evaluates it, so CWE-434's execution precondition is unmet.
  - **Rule:** Acceptance is not execution. Confirm unrestricted file upload by retrieving the stored object at a path an interpreter claims and observing it parsed or executed; storage outside the webroot behind an application handler satisfies OWASP guidance even when the extension is accepted.
