# Upload filename traversal to interpreter-reachable code execution

> goal: `remote_code_execution`
> generated from `db/wks.db` — edit the rows, not this file

Client-controlled upload filename plus an unconstrained extension compose into path traversal followed by interpreter execution, so one weak upload endpoint yields code execution with no second primitive.

## Impact

Remote code execution in the web application's security context from a single multipart POST, potentially low-privileged or unauthenticated.

## Sequence

### 1. Send parent-directory segments in the multipart filename so the stored artifact is written outside the intended upload directory.

**Why it works:** A filename field carrying parent-directory segments escapes the storage directory when the server concatenates the client-supplied name into a filesystem path without canonicalising it.

**Backed by:** `file_upload.technique.traversal_in_upload_filename`

**This step fails if:** If the server strips parent segments from the filename, generates its own name, or resolves the write strictly inside the canonicalised upload directory, the traversal is not present.

### 2. Establish whether the server rewrites the extension or appends its own before treating the traversal as exploitable.

**Why it works:** If the server normalises the extension server-side the traversal lands as an inert object; the traversal-to-execution join requires the extension to survive as supplied.

**Backed by:** `file_upload.fp_rule.extension_not_controlled`

**This step fails if:** If a probe file with a server-appended name and extension lands in a web-served directory and is rendered or executed, the extension IS controllable and the RCE claim holds.

### 3. Request the stored object at the traversed path and confirm whether the interpreter evaluates it rather than returning raw bytes.

**Why it works:** CWE-434's precondition is that the uploaded file is interpreted and executed as code by the recipient; a fetch returning uninterpreted bytes means the join never closed.

**Backed by:** `file_upload.technique.declared_mime_versus_signature_and_lfi_chain`

**This step fails if:** The uploaded temporary file can be included and executed without any further condition, showing the upload endpoint alone yields code execution and no second primitive is required.
