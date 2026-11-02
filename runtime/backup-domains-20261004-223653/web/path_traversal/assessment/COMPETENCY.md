# Methodology — Path Traversal / File Inclusion

> Derived from 27 verified items. Regenerate with `python -m wks.methodgen --class path_traversal --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A filename or path built from user input escapes its intended directory.

**References.** CWE-22 · A01:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.**

Locate the concatenation first: static file handlers, error-page renderers and template loaders that build base plus userValue are the recurring shape. Then confirm the sink actually opens that path and streams the contents back, rather than resolving it against a classpath or resource namespace where the traversal is inert. Probe with a segment count that must exceed the depth of the base directory, and check the response body for content that could only come from outside the served root. Where the sink falls back to a classpath loader, treat a 200 as unproven until a disk-only file reads back.

- *Disproof:* If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557); [snyk.io](https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/)

**The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.**

The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.

HackTricks reference: LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure (pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

- *Disproof:* Refuted if the chain still reaches execution on a host with allow_url_fopen=Off, or on a host with no path-disclosure primitive, or where the sink refuses paths inside the temp directory.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

**Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.**

Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.

HackTricks reference: File Inclusion/Path traversal (pentesting-web/file-inclusion/README.md)

- *Disproof:* Refuted if a target whose ini shows allow_url_include=On rejects a remote URL supplied to the include parameter, or if a target with allow_url_include=Off happily includes one.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/howto/static-files/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md)

**Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.**

Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.

HackTricks reference: LFI2RCE via Nginx temp files (pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

- *Disproof:* Refuted if /proc/<pid>/cmdline reads come back empty or error out through an LFI sink that successfully returns other known local files, showing the file inclusion cannot enumerate process metadata.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.**

On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.

HackTricks reference: File Inclusion/Path traversal (pentesting-web/file-inclusion/README.md)

- *Disproof:* Refuted if the listing appears for a path that contains no traversal payload at all, or if the response for a non-existent path is identical to the response for the traversal path.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/howto/static-files/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md)

**The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.**

The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.

HackTricks reference: LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure (pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

- *Disproof:* Refuted if the file inclusion succeeds repeatedly while the temp directory is non-writable and open_basedir is active, or if the disclosure output is clearly buffered yet the path still arrives at the tester.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When an LFI sink targets the temporary backing file by its own local pathname, the file inclusion consumes the raw request body as written before the decompression wrapper runs, so a payload that only becomes valid after decompression will not execute.**

When an LFI sink targets the temporary backing file by its own local pathname, the file inclusion consumes the raw request body as written before the decompression wrapper runs, so a payload that only becomes valid after decompression will not execute.

HackTricks reference: LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure (pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

- *Disproof:* Refuted if the same file inclusion executes a payload that is only well-formed after the decompression step, which would show the LFI consumed the decoded stream rather than the stored raw bytes.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

**The in-flight request body is reachable through the process file-descriptor table, so once /proc walking yields fd paths, feeding those paths straight into the LFI parameter includes the buffered request bytes directly.**

The in-flight request body is reachable through the process file-descriptor table, so once /proc walking yields fd paths, feeding those paths straight into the LFI parameter includes the buffered request bytes directly.

HackTricks reference: LFI2RCE via Nginx temp files (pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

- *Disproof:* Refuted if the discovered fd paths return empty or non-executable content through the sink, or return whatever file the descriptor points at rather than the buffered request body.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

**A directory listing from a traversal probe is only a map, not a result - the real file surface is reached by pushing the discovered folder name through the LFI sink and seeing whether it resolves to server-side files.**

A directory listing from a traversal probe is only a map, not a result - the real file surface is reached by pushing the discovered folder name through the LFI sink and seeing whether it resolves to server-side files.

HackTricks reference: File Inclusion/Path traversal (pentesting-web/file-inclusion/README.md)

- *Disproof:* Refuted if the discovered folder name through the LFI sink errors out while other known local files resolve fine, or if the listing is a static client-side index that does not correspond to any server-side path.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/howto/static-files/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md)

**Because the tester cannot predict the temporary filename, the practical approach is to hold an LFI request open indefinitely and brute-force candidate names inside that window, converting connection lifetime into a search budget.**

Because the tester cannot predict the temporary filename, the practical approach is to hold an LFI request open indefinitely and brute-force candidate names inside that window, converting connection lifetime into a search budget.

HackTricks reference: LFI2RCE via Eternal waiting (pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

- *Disproof:* Refuted if the server or an intermediary aborts the long-lived request well before the candidate space is covered, or if the request terminates on the first miss instead of continuing through the list.
- *Evidence:* high_confidence — [man7.org](https://man7.org/linux/man-pages/man2/open.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

**When a single temp file does not live long enough to be caught by the LFI, saturating the workers with concurrent requests widens the window so at least one buffered body file survives for the file inclusion to reach.**

When a single temp file does not live long enough to be caught by the LFI, saturating the workers with concurrent requests widens the window so at least one buffered body file survives for the file inclusion to reach.

HackTricks reference: LFI2RCE via Nginx temp files (pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

- *Disproof:* Refuted if raising concurrency changes nothing about how often the fd-path file inclusion catches a temp file, or if the added load recycles workers so file lifetime shrinks rather than grows.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

**Including an attacker-influenced path lets an absolute path such as /etc/passwd or the Windows hosts file be read without any traversal sequence at all.**

In practice on HTB this shows up as: | `/index.php?language=....//....//....//....//etc/passwd` | Bypass basic path traversal filter |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | Bypass filters with URL encoding |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with null byte (obsolete) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | Read PHP with base64 filter |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/28. File Inclusion/File Inclusion.md (973 words, classified web).

- *Disproof:* Refuted when the application validates the path against an allow-list of permitted directories rather than rejecting traversal sequences, in which case an absolute path outside the allow-list is refused.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/28.%20File%20Inclusion/File%20Inclusion.md)

**Once the held-open behaviour is confirmed in the lab or on the target version, scattering thousands of timed-out uploads raises the odds that one of those candidates is caught by the LFI, using fewer long-lived connections than brute force would.**

Once the held-open behaviour is confirmed in the lab or on the target version, scattering thousands of timed-out uploads raises the odds that one of those candidates is caught by the LFI, using fewer long-lived connections than brute force would.

HackTricks reference: LFI2RCE via Eternal waiting (pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

- *Disproof:* Refuted if the same held-open behaviour cannot be reproduced on the target version, or if repeated uploads leave nothing retrievable because cleanup deletes every candidate before the include lands.
- *Evidence:* high_confidence — [man7.org](https://man7.org/linux/man-pages/man2/open.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

**php://filter with a base64-encode conversion stream reads a PHP source file as base64, turning a file read into source disclosure that reveals credentials inside the code.**

In practice on HTB this shows up as: | `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with null byte (obsolete) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | Read PHP with base64 filter |
## Remote Code Execution

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/28. File Inclusion/File Inclusion.md (973 words, classified web).

- *Disproof:* Refuted when the wrapper scheme is disabled or the allow-list excludes any path containing a stream wrapper, in which case the request returns no source text.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/file-path-traversal); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/28.%20File%20Inclusion/File%20Inclusion.md)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Behaviour on a static-file prefix says nothing about a parameterised download handler, and the reverse holds too - each endpoint needs its own probe because the two are served by different code entirely.**

Django's description of its development static helper makes the split explicit and it generalises to every stack: the helper works only in debug mode and only if the given prefix is local, and it only serves the actual STATIC_ROOT folder, it doesn't perform static files discovery, and static files are served via a wrapper at the WSGI application layer so static files requests do not pass through the normal middleware chain. Three consequences for a hunter. A static prefix that returns 403 or 404 for ../ proves nothing about the media or download handler, because different code serves it. Middleware-based authorisation and logging do not run on the static route at all, so the absence of an auth check there is not a finding either. And the user-upload media handler is a separate surface entirely - during development you can serve user-uploaded files from MEDIA_ROOT, and that endpoint takes an attacker-supplied filename by design. Test each file-serving surface on its own terms.

- *Disproof:* The claim is false when both surfaces are served by the same confined component - a single static-file handler in front of every asset class, or a CDN or object-store gateway that applies one prefix rule to all buckets - in which case the static route's behaviour is genuinely informative about the download route. It also fails when the static surface is served by the web server itself from a document root, since the server's own path handling is a separate implementation and equally consistent across every alias it serves. And a specific finding on either endpoint still stands on its own evidence; this rule is only about the transfer of conclusions between endpoints.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/howto/static-files/); [werkzeug.palletsprojects.com](https://werkzeug.palletsprojects.com/en/stable/utils/)

**Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.**

A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not. Replace the calibration probe with a path that exists only on the filesystem, and confirm it reads back only when the disk branch is live. Prefer a harmless marker file over a credential or key so the validation leaves no secret in the scan log, and re-run the identical request to show the effect is reproducible.

- *Disproof:* If a file that exists only on disk returns 404 or an error while the bundled asset returns 200, the read comes from the classpath and the finding is not actionable on that host.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557); [projectdiscovery.io](https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.**

Discard the finding when your encoded or dot-segment payload returns byte-identical content to the same request with a harmless filename, because the response is the normalized path, a redirect, or a fixed error page rather than a different file. The finding survives when the traversal returns content you can only have reached by leaving the intended directory, such as a system file or a config with credentials, and when the same payload works on more than one traversal encoding.

- *Disproof:* If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [projectdiscovery.io](https://projectdiscovery.io/blog/nuclei-templates-april-2026)

**A filename=../../../etc/passwd payload sent in a URL path segment or a multipart/form-data filename that the front-end web server removes before the application sees it is not path traversal, because the ../ sequence that would escape the base directory is neutralised upstream of the filesystem call and the read resolves inside the intended directory.**

Mechanism: CWE-22 requires the special element to survive into the pathname the product constructs; in the common deployment the HTTP layer (front proxy, servlet container, or the framework's own multipart parser) collapses or strips ../ in the request path and in the uploaded filename before application code builds the file path, so new File(base, userInput) or fopen() receives a name with the traversal already gone and reads a sibling inside the base directory (often a 404). The check that separates the two cases is to observe what the handler received, not what was transmitted: compare the raw request bytes with the value logged/echoed by the application, or re-issue the payload double-encoded (%252e%252e%252f) and through a non-stripped context such as a query parameter. If the payload only changes behaviour when a second decode reintroduces the sequence, the finding is about decoding/normalisation order, not about a reachable ../ in the pathname.

- *Disproof:* The rule stops being true when a context exists in which the sequence is not stripped — a query-string or JSON body parameter, a header such as X-Forwarded-Prefix, a filename that arrives base64- or multipart-encoded and is decoded by application code, or a second proxy hop that does not normalise — because then ../ does reach the pathname constructor and the resolved path leaves the restricted directory, which is exactly the CWE-22 condition.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**A response whose echoed path has ./ and ../ components stripped is consistent with normalisation by the client, the server, the framework, or the terminal - it does not by itself evidence an input filter, and it is not proof the traversal failed either.**

The corpus already holds the differential rule that a normalised payload returning identical content is uninformative; this is the complementary trap. When you submit ../../etc/passwd and the error message shows ../ cleaned to / or the path rendered canonicalised, the tempting reading is 'a filter caught it', and the report gets written as a mitigation. The alternative readings are at least as likely: the URL library parsed and re-serialised the path, the framework logged the normalised form, the terminal or the shell echoed a resolved path, or the browser sent a canonicalised request before it ever reached the server. The kernel documentation reminds you that path handling has more than one stage - components are separated from slashes, and each component is resolved with rules of its own - so a cleaned echo is evidence about one stage at most. The reportable observation is the file content, and the absence of a filter is only established by a payload that traverses successfully through a different encoding or separator.

- *Disproof:* The claim is false when the normalisation is provably server-side and effective - you can show the request as received by the origin, for example through a request log or a reflected value that only the server could have computed, and the traversal payload in that same form still fails, which is a genuine control. It is also false where the client is not in the picture at all: a request made from a script with a raw socket, a binary body carrying the path, or a file upload field bypasses any browser canonicalisation, so evidence from that channel is not subject to this ambiguity. And a genuinely successful read is a finding regardless of how many stages normalised the string on the way in, because the read happened.
- *Evidence:* high_confidence — [kernel.org](https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html); [man7.org](https://man7.org/linux/man-pages/man2/open.2.html)

**A user-supplied filename joined to a base directory and then canonicalised with a platform API (realpath, Path.getCanonicalPath, GetFullPath, abs_path) whose result still begins with the expected base directory is not path traversal, because canonicalisation resolves the .. segments and symlinks and the read stays inside the restricted directory the check named.**

Mechanism: the containment test is applied to the canonical path, not to the raw string, so ../../etc/passwd collapses to <base>/etc/passwd and passes the startsWith(BASE_DIRECTORY) prefix test while a sibling directory that merely shares the base prefix (/var/www/images_evil) does not. The check that distinguishes false from true positives is therefore: canonicalise first, then compare the canonical result against the canonical base with a separator-aware prefix test, and confirm the file actually returned belongs to the base subtree. A scanner that flags every request containing ../ misses the point of the rule — the finding is false whenever the file served is inside the allowed directory, and the residual issue is only that error messages may disclose paths. The same rule explains why an absolute-path attempt (/etc/passwd) that the join collapses back under the base is also not traversal.

- *Disproof:* The rule is wrong when canonicalisation happens before validation rather than after (encoding introduced after the check), when the prefix test is a bare string compare so that /var/www/images_evil passes a check against /var/www/images, when the canonical base itself is attacker-influenced (a symlinked upload directory or a user-supplied base), when a TOCTOU swap replaces the validated path component before the open, or when the sink is not the filesystem but a shell, an include statement or an archive extractor that re-interprets the un-canonicalised string.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.**

Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory. The bypass is proven when the encoded form returns a file body the literal form is rejected from, because characters other than the reserved set are equivalent to their percent-encoded octets, so the two forms can differ as strings while naming the same normalized path. Note that a filter which decodes once and a backend which normalizes twice is the common shape of this bypass, and comparing as a simple string versus syntax-based normalization is exactly where the two disagree.

- *Disproof:* If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [httpwg.org](https://httpwg.org/specs/rfc9110.html)

**Confining the resolved path under a base directory by string prefix does not contain a symbolic link, because resolving the link replaces the component and discards all preceding parts of the path when the link body is absolute.**

The kernel's own description of symlink resolution is the mechanism, and it is why every prefix check on a resolved path is best-effort. Conceptually symbolic links could be handled by editing the path; if a component name refers to a symbolic link, then that component is replaced by the body of the link and, if that body starts with a '/', then all preceding parts of the path are discarded. So an attacker who can write one entry inside an otherwise-confined directory - through an upload feature, an archive extraction that preserves links, a build artefact, a cache directory, or a shared volume - plants a link to /etc/passwd and every later request that reads through it lands outside the base directory while every string in the request looks clean. The hunting technique follows directly: confirm the confined directory is writable by the attacker, then look for link creation in the upload or extract path, and prove the read by fetching content only the link target could serve. Note the same applies to archive extraction, which is the most common way these links appear in practice.

- *Disproof:* The claim is false when the open itself is confined below the base rather than merely checked - resolving with an openat-style call relative to a directory file descriptor for the base directory, so the kernel performs component resolution with that directory as the root and cannot escape it by any path, because a '..' or an absolute link body cannot climb above the descriptor. It is also false where the service runs with a chroot, a container mount namespace, or a filesystem sandbox that makes the out-of-tree target unreadable, in which case the symlink exists but reaches nothing. And the finding needs the write: an attacker-controlled directory that is not writable gives no place to plant the link, so a report without a demonstrated link creation is a hypothesis.
- *Evidence:* high_confidence — [kernel.org](https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html); [werkzeug.palletsprojects.com](https://werkzeug.palletsprojects.com/en/stable/utils/)

**A local file inclusion filter that strips '../' is bypassed by re-encoding the traversal (%2e%2e%2f), because the filter matches the decoded form the request never carries.**

In practice on HTB this shows up as: | **LFI Bypasses** |
| `/index.php?language=....//....//....//....//etc/passwd` | Bypass basic path traversal filter |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | Bypass filters with URL encoding |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with null byte (obsolete) |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/28. File Inclusion/File Inclusion.md (973 words, classified web).

- *Disproof:* Refuted when the server percent-decodes the parameter before filtering, in which case the encoded sequence is normalised to ../ and rejected; the bypass only exists where filtering happens on the raw, undecoded request value.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/file-path-traversal); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/28.%20File%20Inclusion/File%20Inclusion.md)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 7. Impact

_What is actually demonstrable, and what to stop claiming._

**An LFI sink is an execution primitive rather than a read primitive, so the moment it can be pointed at a file the tester controls the included content runs with the web server's privileges.**

An LFI sink is an execution primitive rather than a read primitive, so the moment it can be pointed at a file the tester controls the included content runs with the web server's privileges.

HackTricks reference: LFI2RCE via Eternal waiting (pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

- *Disproof:* Refuted if the sink returns the uploaded file's content as inert data without executing, for example because the include is downgraded to a read or the file's extension is never interpreted.
- *Evidence:* high_confidence — [man7.org](https://man7.org/linux/man-pages/man2/open.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
