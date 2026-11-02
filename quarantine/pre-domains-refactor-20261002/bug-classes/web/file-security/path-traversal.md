# Path Traversal / File Inclusion

## Definition

A filename or path built from user input escapes its intended directory.

- **CWE:** CWE-22
- **OWASP:** A01:2021
- **Surface:** web
- **Aliases:** ["path traversal", "directory traversal", "lfi", "rfi", "file inclusion"]

Canonical home for `path_traversal`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.**

Locate the concatenation first: static file handlers, error-page renderers and template loaders that build base plus userValue are the recurring shape. Then confirm the sink actually opens that path and streams the contents back, rather than resolving it against a classpath or resource namespace where the traversal is inert. Probe with a segment count that must exceed the depth of the base directory, and check the response body for content that could only come from outside the served root. Where the sink falls back to a classpath loader, treat a 200 as unproven until a disk-only file reads back.

*Disproof:* If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

Not yet researched.

## Variations

**A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.**

Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory. The bypass is proven when the encoded form returns a file body the literal form is rejected from, because characters other than the reserved set are equivalent to their percent-encoded octets, so the two forms can differ as strings while naming the same normalized path. Note that a filter which decodes once and a backend which normalizes twice is the common shape of this bypass, and comparing as a simple string versus syntax-based normalization is exactly where the two disagree.

*Disproof:* If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A filename you supplied appearing in a traversal error page or a session cookie is not a file read; the finding needs file CONTENT returned as the response body.**

Discard the report when the only artefact is your own filename echoed back in an error message, a stack trace, a directory listing of the web root, or a session cookie dropped on a custom 404 page, because none of those read a file outside the intended root. The finding survives when the response body contains data from the targeted file and that content differs from anything served by the same route with a legitimate name.

*Disproof:* If the same route serves a fixed placeholder body for every nonexistent path including your traversal form, the identical-response rule applies and the report is a false positive; if any one form returns real file bytes, the finding is real regardless of what the other forms did.

**A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.**

Discard the finding when your encoded or dot-segment payload returns byte-identical content to the same request with a harmless filename, because the response is the normalized path, a redirect, or a fixed error page rather than a different file. The finding survives when the traversal returns content you can only have reached by leaving the intended directory, such as a system file or a config with credentials, and when the same payload works on more than one traversal encoding.

*Disproof:* If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.

## Validation

**Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.**

A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not. Replace the calibration probe with a path that exists only on the filesystem, and confirm it reads back only when the disk branch is live. Prefer a harmless marker file over a credential or key so the validation leaves no secret in the scan log, and re-run the identical request to show the effect is reproducible.

*Disproof:* If a file that exists only on disk returns 404 or an error while the bundled asset returns 200, the read comes from the classpath and the finding is not actionable on that host.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557>
- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities>
  - <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
