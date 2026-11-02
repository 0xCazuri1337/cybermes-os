# Methodology — Unrestricted File Upload

> Derived from 22 verified items. Regenerate with `python -m wks.methodgen --class file_upload --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The server accepts an upload without constraining type, name, location or interpretation.

**References.** CWE-434 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.**

The technique is a two-step chain, and reporting only the first step overstates it. In a documented case, a unrestricted php file upload vulnerability exists in a temporary copy functionality where a specially crafted HTTP request can lead to arbitrary code execution when chained with an LFI vulnerability, requiring a series of HTTP requests. That series is the tell: the upload itself lands an inert temporary copy, and the execution comes from a local file inclusion that includes it by path. That is why an upload-scanner hit on 'unrestricted extension accepted' is not self-sufficient evidence of RCE, and why the second primitive must be named. The same endpoint teaches the cheap defensive control. A scanner that compares declared content types with detected file signatures reduces reliance on user-provided metadata, and inspectors that examine archive contents before extraction, with limits on recursion depth, total file counts, and archive size expansion, are aimed at archive bombs and nested payload delivery. Hunt accordingly: upload a polyglot whose declared type and detected signature disagree, note whether the server keeps the declared type, then attempt to include the stored temporary path and compare the response against a control request for a path that was never uploaded.

- *Disproof:* The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885)

**A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.**

The filename is a second input channel inside the upload request body, separate from the file content, and it is routinely concatenated without validation. Craft the part's filename with leading parent segments and a distinctive extension-free name, then check whether the artefact appears outside the intended directory. Establish which account performs the write, because the writable set is bounded by that account's permissions and determines whether a web directory or a config directory is reachable. Use an inert filename; the goal is to prove the path escape, not to plant anything executable.

- *Disproof:* If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/); [snyk.io](https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/)

**Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.**

In practice on HTB this shows up as: ### Module Summary
Many modern web applications have file upload capabilities, which are usually necessary for the web application's functionality to enable features like attaching files or changing a user's profile image. If the file upload functionality is not securely coded, it may be abused to upload arbitrary files to the back-end server, eventually leading to compromise of the back-end server.
When an attacker can upload arbitrary files to the back-end server, they can upload malicious files, like web shells, which would enable them to execute arbitrary commands on the back-end server. This eventually allows attackers to take control over the entire server and all web applications hosted on it, which makes `File Upload Attacks` among the most critical web vulnerabilities.

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/31c. File Upload Attacks/File Upload Attacks.md (816 words, classified web).

- *Disproof:* Refuted when the upload is stored outside any served or executable path, or the content is rewritten to an inert type, so no interpreter ever executes the uploaded bytes.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [portswigger.net](https://portswigger.net/web-security/file-upload); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31c.%20File%20Upload%20Attacks/File%20Upload%20Attacks.md)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.**

The upload response proves nothing on its own - it confirms the endpoint accepted bytes. Take the stored artifact and go get it back the way the web server would. Step one, resolve the storage path: use the response's returned identifier, filename, or path hint to construct a direct request to the stored object, including traversal forms if the filename was attacker-controlled. Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output. The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type. That is the CWE-434 precondition satisfied, and it is especially true for extensions such as .asp and .php because those file types are often treated as automatically executable even when file system permissions do not specify execution. Refuted outcome: 404 on the direct path, a download served as application/octet-stream through an application handler, or the raw bytes echoed uninterpreted. Also verify the type check itself - the Content-Type for uploaded files is provided by the user and cannot be trusted, so a mismatch between declared type and file signature is a lead, not proof.

- *Disproof:* Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html)

**The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.**

Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.

- *Disproof:* If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [nginx.org](https://nginx.org/en/docs/http/ngx_http_core_module.html)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.**

The lookalike: you POST a .php or .jsp file, the server returns 200 and stores your bytes, and it is filed as unrestricted file upload. CWE-434 states the precondition precisely: arbitrary code execution is possible if an uploaded file is interpreted and executed as code by the recipient. If your upload lands outside the document root and is only ever served back through an application handler that maps an opaque identifier to the stored object, the interpreter never sees it and the precondition is absent. OWASP's guidance is explicit that files should be stored outside the webroot where only administrative access is allowed, and that where public access to the files is needed a handler should be used. The winning test is to resolve the stored object the way a web server would - request the directory the file was written into, request the stored filename directly, and check whether any interpreter-mapped extension reaches it. Only if a direct fetch executes, or a handler emits an executable content type, is the acceptance the vulnerability.

- *Disproof:* Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html)

**Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes.**

Mechanism: Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-declared value, since the attacker controls that field directly and the same request can be replayed with any declared type.

- *Disproof:* It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-declared value, since the attacker controls that field directly and the same request can be replayed with any declared type.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [php.net](https://www.php.net/manual/en/features.file-upload.php)

**The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.**

Mechanism: The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.

- *Disproof:* It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [nginx.org](https://nginx.org/en/docs/http/ngx_http_core_module.html)

**Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension.**

Mechanism: Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.

- *Disproof:* It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [php.net](https://www.php.net/manual/en/features.file-upload.php)

**When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.**

Check whether the final on-disk name is attacker-controlled in its extension before claiming execution. If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges. Escalate to code execution only when the writable set demonstrably includes a file the server itself parses or executes, such as init scripts or the server executable itself. State the privilege bound in the write-up, since a write as an unprivileged service account is a materially different severity than a write into the web root.

- *Disproof:* If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/); [snyk.io](https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another.**

Mechanism: An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.

- *Disproof:* It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [php.net](https://www.php.net/manual/en/features.file-upload.php)

## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An upload endpoint that neither canonicalises the client filename nor constrains the extension chains into path traversal and then interpreter-reachable execution, so a single weak upload control converts into code execution without any second primitive.**

Two existing techniques compose and the second only becomes available because the first failed to normalise its input. The upload half: a multipart filename field containing parent-directory segments escapes the intended storage directory when the server concatenates the client-supplied name into a filesystem path without canonicalising it. The execution half: CWE-434's precondition is that the uploaded file is interpreted and executed as code by the recipient, which is automatic for extensions such as .asp and .php because those types are often treated as executable even when file system permissions do not specify execution. Chained, the traversal decides WHERE the interpreter looks and the extension decides WHETHER it looks, so the missing control is not one setting but two - filename normalisation and extension allowlisting. OWASP states both halves as separate defences: store files outside the webroot where only administrative access is allowed, and list allowed extensions, allowing only safe and critical extensions for business functionality. The Content-Type is a trap rather than a defence, since it is provided by the user and cannot be trusted. The chain therefore ends in a verified outcome, not an assumed one: retrieve the stored object at the traversed path and confirm the interpreter evaluated it.

- *Disproof:* Refuted if the server canonicalises the multipart filename to a basename before touching the filesystem, or if the storage directory lies outside every interpreter-mapped document root; either control alone breaks the traversal-to-execution join even when the other is missing.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html)

## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.**

End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.

HackTricks reference: file upload (https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md)

- *Disproof:* Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md); [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/)

**Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.**

Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.

HackTricks reference: file upload (https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md)

- *Disproof:* The accepted file is renamed, stored outside any executable path and served back as inert content with no execution on the server.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md); [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
