# Unrestricted File Upload

## Definition

The server accepts an upload without constraining type, name, location or interpretation.

- **CWE:** 434
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["file upload", "unrestricted upload", "web shell upload"]

Canonical home for `file_upload`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**An upload endpoint that stores an attacker-supplied .php under a temporary name is only exploitable when a second primitive reaches it; the same request pair also shows why declared MIME must be compared against the detected file signature.**

The technique is a two-step chain, and reporting only the first step overstates it. In a documented case, a unrestricted php file upload vulnerability exists in a temporary copy functionality where a specially crafted HTTP request can lead to arbitrary code execution when chained with an LFI vulnerability, requiring a series of HTTP requests. That series is the tell: the upload itself lands an inert temporary copy, and the execution comes from a local file inclusion that includes it by path. That is why an upload-scanner hit on 'unrestricted extension accepted' is not self-sufficient evidence of RCE, and why the second primitive must be named. The same endpoint teaches the cheap defensive control. A scanner that compares declared content types with detected file signatures reduces reliance on user-provided metadata, and inspectors that examine archive contents before extraction, with limits on recursion depth, total file counts, and archive size expansion, are aimed at archive bombs and nested payload delivery. Hunt accordingly: upload a polyglot whose declared type and detected signature disagree, note whether the server keeps the declared type, then attempt to include the stored temporary path and compare the response against a control request for a path that was never uploaded.

*Disproof:* The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.

**A multipart filename field containing parent-directory segments escapes the upload directory when the server concatenates the client filename onto a base path.**

The filename is a second input channel inside the upload request body, separate from the file content, and it is routinely concatenated without validation. Craft the part's filename with leading parent segments and a distinctive extension-free name, then check whether the artefact appears outside the intended directory. Establish which account performs the write, because the writable set is bounded by that account's permissions and determines whether a web directory or a config directory is reachable. Use an inert filename; the goal is to prove the path escape, not to plant anything executable.

*Disproof:* If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `upload-traversal-to-interpreter-execution` — Upload filename traversal to interpreter-reachable code execution (goal: `remote_code_execution`)

## Real-World Examples

Not yet researched.

## Common False Positives

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

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/434.html>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2026/02/02/pompelmi-open-source-secure-file-upload-scanning-node-js/>
- **nccgroup.com** (report)
  - <https://www.nccgroup.com/research/technical-advisory-sonicwall-sma-100-series-unauthenticated-file-upload-path-traversal-cve-2021-20040/>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1885>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
