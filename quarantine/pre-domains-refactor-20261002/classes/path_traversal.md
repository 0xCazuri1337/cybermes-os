# Path Traversal / File Inclusion

> surface: `web` · CWE: CWE-22 · OWASP: A01:2021
> maturity: **researching** — 6 items, 6 supported, 2 FP rules, 0 chains

A filename or path built from user input escapes its intended directory.

**Aliases:** path traversal, directory traversal, lfi, rfi, file inclusion

## Prerequisite

- **Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.**  
  `high_confidence` · score 0.9015 · disproved by: If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
  sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>

## Technique

- **In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>

## Validation

- **Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.**  
  `high_confidence` · score 0.874 · disproved by: If a file that exists only on disk returns 404 or an error while the bundled asset returns 200, the read comes from the classpath and the finding is not actionable on that host.
  sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities>

## Fp Rule

- **A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.**  
  `high_confidence` · score 0.929 · disproved by: If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.
  sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
- **A filename you supplied appearing in a traversal error page or a session cookie is not a file read; the finding needs file CONTENT returned as the response body.**  
  `high_confidence` · score 0.8465 · disproved by: If the same route serves a fixed placeholder body for every nonexistent path including your traversal form, the identical-response rule applies and the report is a false positive; if any one form returns real file bytes, the finding is real regardless of what the other forms did.
  sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>

## Bypass

- **A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.**  
  `high_confidence` · score 0.984 · disproved by: If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013>

## Known gaps

Not yet satisfied: `items`, `chain`
