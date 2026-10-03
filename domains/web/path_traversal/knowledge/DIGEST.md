# Path Traversal / File Inclusion

> surface: `web` · CWE: CWE-22 · OWASP: A01:2021
> maturity: **mature** — 33 items, 33 supported, 2 FP rules, 1 chains

A filename or path built from user input escapes its intended directory.

**Aliases:** path traversal, directory traversal, lfi, rfi, file inclusion

## Prerequisite

- **Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.**  
  `high_confidence` · score 0.9015 · disproved by: If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
  sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>

## Technique

- **This could allow an attacker to upload any executable file or other file with malicious code.**  
  `high_confidence` · score 0.833 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This could allow an attacker to upload any executable file or other file with malicious co".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory.**  
  `high_confidence` · score 0.833 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since the code does not check the filename that is provided in the header, an attacker can".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: library file sends a redirect if it is directly requested but continues to execute,".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **Notice how this code also contains an error message information leak ( CWE-209 ) if the user parameter does not produce a file that exists: the full pathname is provided.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Notice how this code also contains an error message information leak ( CWE-209 ) if the us".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the file path should be validated and restricted to a specific directory to preve".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **Chain: external control of values for user's desired language and theme enables path traversal.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: external control of values for user's desired language and theme enables path trave".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **Bulletin board allows attackers to determine the existence of files using the avatar.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Bulletin board allows attackers to determine the existence of files using the avatar.".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Otherwise, store them in a separate directory and use the web server's access control capa".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if an attacker provides ../../../../etc/passwd as input, the script will fetc".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the targeted file is used for a security mechanism, then the attacker may be able to by".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
- **The attacker may be able read the contents of unexpected files and expose sensitive data.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker may be able read the contents of unexpected files and expose sensitive data.".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
- **By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By using special elements such as ".." and "/" separators, attackers can escape outside of".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
- **In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ).**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The path is checked against an expected directory (/home/cwe/documents); otherwise, an att".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If errors must be captured in some detail, record them in log messages, but consider what ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file ( CWE-306 ), then uses .. path traversal sequences ( CWE-23 ) in the file to access unexpected files, as exploited in the wild per CISA KEV.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: Cloud computing virtualization platform does not require authentication for upload ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to apply to a wider range of files.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In many programming languages, the injection of a null byte (the 0 or NUL) may allow an at".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the path is not validated or modified to prevent it from containing relative or a".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With this version of the script, if the current working directory is /home/cwe/documents, ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if the user supplies an absolute path, the os.path.join() function will discard t".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **This may prevent the product from working at all and in the case of protection mechanisms such as authentication, it has the potential to lock out product users.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may prevent the product from working at all and in the case of protection mechanisms ".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if the current working directory is /home/user/documents, but the user inputs".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **This can give attackers enough room to bypass the intended validation.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
- **For example, appending a new account at the end of a password file may allow an attacker to bypass authentication.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, appending a new account at the end of a password file may allow an attacker t".
  sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
- **Ideally, the path should be resolved relative to some kind of application or user home directory.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the path should be resolved relative to some kind of application or user home dir".
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
