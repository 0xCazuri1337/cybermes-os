# Methodology — Path Traversal / File Inclusion

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class path_traversal --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A filename or path built from user input escapes its intended directory.

**References.** CWE-22 · A01:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.**

Locate the concatenation first: static file handlers, error-page renderers and template loaders that build base plus userValue are the recurring shape. Then confirm the sink actually opens that path and streams the contents back, rather than resolving it against a classpath or resource namespace where the traversal is inert. Probe with a segment count that must exceed the depth of the base directory, and check the response body for content that could only come from outside the served root. Where the sink falls back to a classpath loader, treat a 200 as unproven until a disk-only file reads back.

- *Disproof:* If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557); [snyk.io](https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**

chances of success. 
 If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. Highly sensitive information such as passwords should never be saved to log files. 
 Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a user account exists or not. 
 In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. 
 
 
 
 
 
 
 
 
 
 
 Operation; Implementation 
 
 
 
 
 
 
 Strategy: Environment Hardening 
 
 
 When using PHP, configure the application so that it does not use register_globals. During implementation, develop the application so that it does not rely on this feature, but be wary of implementing a register_globals emulation that is subject to weaknesses such as CWE-95 , CWE-621 , and similar

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.**

A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not. Replace the calibration probe with a path that exists only on the filesystem, and confirm it reads back only when the disk branch is live. Prefer a harmless marker file over a credential or key so the validation leaves no secret in the scan log, and re-run the identical request to show the effect is reproducible.

- *Disproof:* If a file that exists only on disk returns 404 or an error while the bundled asset returns 200, the read comes from the classpath and the finding is not actionable on that host.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557); [projectdiscovery.io](https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.**

Discard the finding when your encoded or dot-segment payload returns byte-identical content to the same request with a harmless filename, because the response is the normalized path, a redirect, or a fixed error page rather than a different file. The finding survives when the traversal returns content you can only have reached by leaving the intended directory, such as a system file or a config with credentials, and when the same payload works on more than one traversal encoding.

- *Disproof:* If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [projectdiscovery.io](https://projectdiscovery.io/blog/nuclei-templates-april-2026)

**A filename you supplied appearing in a traversal error page or a session cookie is not a file read; the finding needs file CONTENT returned as the response body.**

Discard the report when the only artefact is your own filename echoed back in an error message, a stack trace, a directory listing of the web root, or a session cookie dropped on a custom 404 page, because none of those read a file outside the intended root. The finding survives when the response body contains data from the targeted file and that content differs from anything served by the same route with a legitimate name.

- *Disproof:* If the same route serves a fixed placeholder body for every nonexistent path including your traversal form, the identical-response rule applies and the report is a false positive; if any one form returns real file bytes, the finding is real regardless of what the other forms did.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [projectdiscovery.io](https://projectdiscovery.io/blog/nuclei-templates-april-2026)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.**

Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory. The bypass is proven when the encoded form returns a file body the literal form is rejected from, because characters other than the reserved set are equivalent to their percent-encoded octets, so the two forms can differ as strings while naming the same normalized path. Note that a filter which decodes once and a backend which normalizes twice is the common shape of this bypass, and comparing as a simple string versus syntax-based normalization is exactly where the two disagree.

- *Disproof:* If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013); [httpwg.org](https://httpwg.org/specs/rfc9110.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
