# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 33 (supported 33), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 33 (supported 33), FP rules 2, chains 1, state mature

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -133,4 +133,4 @@
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013>
 
 ---
-Full class document: `domains/web/path_traversal/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id path_traversal`
+Full class document: `domains/web/path_traversal/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id path_traversal`
```

## 2026-10-02 19:37 — 153 diff lines
- items: 36 (supported 7), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-22 · OWASP A01:2021
-> evidence: 33 items, 33 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 36 items, 7 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 A filename or path built from user input escapes its intended directory.
 
@@ -26,90 +26,102 @@
 
 ## Techniques (what to change)
 
-- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.
+- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- This could allow an attacker to upload any executable file or other file with malicious code.
+- This could allow an attacker to upload any executable file or other file with malicious code. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This could allow an attacker to upload any executable file or other file with malicious co".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ).
+- The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The path is checked against an expected directory (/home/cwe/documents); otherwise, an att".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.
+- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory.
+- Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since the code does not check the filename that is provided in the header, an attacker can".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal.
+- Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: library file sends a redirect if it is directly requested but continues to execute,".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Notice how this code also contains an error message information leak ( CWE-209 ) if the user parameter does not produce a file that exists: the full pathname is provided.
+- Notice how this code also contains an error message information leak ( CWE-209 ) if the user parameter does not produce a file that exists: the full pathname is provided. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Notice how this code also contains an error message information leak ( CWE-209 ) if the us".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism.
+- If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the targeted file is used for a security mechanism, then the attacker may be able to by".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
-- If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers.
+- If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If errors must be captured in some detail, record them in log messages, but consider what ".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.
+- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- The attacker may be able read the contents of unexpected files and expose sensitive data.
+- The attacker may be able read the contents of unexpected files and expose sensitive data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker may be able read the contents of unexpected files and expose sensitive data.".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
-- Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access.
+- Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the file path should be validated and restricted to a specific directory to preve".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file ( CWE-306 ), then uses .. path traversal sequences ( CWE-23 ) in the file to access unexpected files, as exploited in the wild per CISA KEV.
+- Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file ( CWE-306 ), then uses .. path traversal sequences ( CWE-23 ) in the file to access unexpected files, as exploited in the wild per CISA KEV. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: Cloud computing virtualization platform does not require authentication for upload ".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to apply to a wider range of files.
+- In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to apply to a wider range of files. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In many programming languages, the injection of a null byte (the 0 or NUL) may allow an at".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Chain: external control of values for user's desired language and theme enables path traversal.
+- Chain: external control of values for user's desired language and theme enables path traversal. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: external control of values for user's desired language and theme enables path trave".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object.
+- However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the path is not validated or modified to prevent it from containing relative or a".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd.
+- With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With this version of the script, if the current working directory is /home/cwe/documents, ".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system.
+- By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By using special elements such as ".." and "/" separators, attackers can escape outside of".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
-- However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided.
+- However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if the user supplies an absolute path, the os.path.join() function will discard t".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Bulletin board allows attackers to determine the existence of files using the avatar.
+- Bulletin board allows attackers to determine the existence of files using the avatar. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Bulletin board allows attackers to determine the existence of files using the avatar.".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- This may prevent the product from working at all and in the case of protection mechanisms such as authentication, it has the potential to lock out product users.
+- This may prevent the product from working at all and in the case of protection mechanisms such as authentication, it has the potential to lock out product users. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may prevent the product from working at all and in the case of protection mechanisms ".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them.
+- Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Otherwise, store them in a separate directory and use the web server's access control capa".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path.
+- For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if the current working directory is /home/user/documents, but the user inputs".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- This can give attackers enough room to bypass the intended validation.
+- This can give attackers enough room to bypass the intended validation. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file.
+- For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if an attacker provides ../../../../etc/passwd as input, the script will fetc".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- For example, appending a new account at the end of a password file may allow an attacker to bypass authentication.
+- For example, appending a new account at the end of a password file may allow an attacker to bypass authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, appending a new account at the end of a password file may allow an attacker t".
... (truncated)
```

## 2026-10-03 01:46 — 132 diff lines
- items: 56 (supported 25), FP rules 2, chains 1, state mature

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-22 · OWASP A01:2021
-> evidence: 36 items, 7 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: fp_rules
+> evidence: 56 items, 25 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 A filename or path built from user input escapes its intended directory.
 
@@ -20,9 +20,27 @@
 
 ## Prerequisites (do not start without these)
 
+- The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.
+  - **Disproof:** Refuted if the chain still reaches execution on a host with allow_url_fopen=Off, or on a host with no path-disclosure primitive, or where the sink refuses paths inside the temp directory.
+  - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md>
+- Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.
+  - **Disproof:** Refuted if /proc/<pid>/cmdline reads come back empty or error out through an LFI sink that successfully returns other known local files, showing the file inclusion cannot enumerate process metadata.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md>
+- Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.
+  - **Disproof:** Refuted if a target whose ini shows allow_url_include=On rejects a remote URL supplied to the include parameter, or if a target with allow_url_include=Off happily includes one.
+  - Sources: <https://docs.djangoproject.com/en/5.0/howto/static-files/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md>
 - Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.
   - **Disproof:** If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
   - Sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
+
+## Recon signals (where to look)
+
+- On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.
+  - **Disproof:** Refuted if the listing appears for a path that contains no traversal payload at all, or if the response for a non-existent path is identical to the response for the traversal path.
+  - Sources: <https://docs.djangoproject.com/en/5.0/howto/static-files/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md>
+- The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.
+  - **Disproof:** Refuted if the file inclusion succeeds repeatedly while the temp directory is non-writable and open_basedir is active, or if the disclosure output is clearly buffered yet the path still arrives at the tester.
+  - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md>
 
 ## Techniques (what to change)
 
@@ -110,27 +128,60 @@
 - That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".
   - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
+- A directory listing from a traversal probe is only a map, not a result - the real file surface is reached by pushing the discovered folder name through the LFI sink and seeing whether it resolves to server-side files.
+  - **Disproof:** Refuted if the discovered folder name through the LFI sink errors out while other known local files resolve fine, or if the listing is a static client-side index that does not correspond to any server-side path.
+  - Sources: <https://docs.djangoproject.com/en/5.0/howto/static-files/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md>
+- The in-flight request body is reachable through the process file-descriptor table, so once /proc walking yields fd paths, feeding those paths straight into the LFI parameter includes the buffered request bytes directly.
+  - **Disproof:** Refuted if the discovered fd paths return empty or non-executable content through the sink, or return whatever file the descriptor points at rather than the buffered request body.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md>
+- Because the tester cannot predict the temporary filename, the practical approach is to hold an LFI request open indefinitely and brute-force candidate names inside that window, converting connection lifetime into a search budget.
+  - **Disproof:** Refuted if the server or an intermediary aborts the long-lived request well before the candidate space is covered, or if the request terminates on the first miss instead of continuing through the list.
+  - Sources: <https://man7.org/linux/man-pages/man2/open.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md>
+- Once the held-open behaviour is confirmed in the lab or on the target version, scattering thousands of timed-out uploads raises the odds that one of those candidates is caught by the LFI, using fewer long-lived connections than brute force would.
+  - **Disproof:** Refuted if the same held-open behaviour cannot be reproduced on the target version, or if repeated uploads leave nothing retrievable because cleanup deletes every candidate before the include lands.
+  - Sources: <https://man7.org/linux/man-pages/man2/open.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md>
+- When an LFI sink targets the temporary backing file by its own local pathname, the file inclusion consumes the raw request body as written before the decompression wrapper runs, so a payload that only becomes valid after decompression will not execute.
+  - **Disproof:** Refuted if the same file inclusion executes a payload that is only well-formed after the decompression step, which would show the LFI consumed the decoded stream rather than the stored raw bytes.
+  - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md>
+- When a single temp file does not live long enough to be caught by the LFI, saturating the workers with concurrent requests widens the window so at least one buffered body file survives for the file inclusion to reach.
+  - **Disproof:** Refuted if raising concurrency changes nothing about how often the fd-path file inclusion catches a temp file, or if the added load recycles workers so file lifetime shrinks rather than grows.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md>
+- Including an attacker-influenced path lets an absolute path such as /etc/passwd or the Windows hosts file be read without any traversal sequence at all.
+  - **Disproof:** Refuted when the application validates the path against an allow-list of permitted directories rather than rejecting traversal sequences, in which case an absolute path outside the allow-list is refused.
+  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/28.%20File%20Inclusion/File%20Inclusion.md>
+- php://filter with a base64-encode conversion stream reads a PHP source file as base64, turning a file read into source disclosure that reveals credentials inside the code.
+  - **Disproof:** Refuted when the wrapper scheme is disabled or the allow-list excludes any path containing a stream wrapper, in which case the request returns no source text.
+  - Sources: <https://portswigger.net/web-security/file-path-traversal> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/28.%20File%20Inclusion/File%20Inclusion.md>
 
 ## Tests
 
-- To decide this case, observe: ropped on a custom 404 page, because none of those read a file outside the intended root. The finding survives when the response body contains data from the targeted file and that content differs from anything served by the same route with a legitimate name.
+- To decide this case, observe: Discard the report when the only artefact is your own filename echoed back in an error message, a stack trace, a directory listing of the web root, or a session cookie dropped on a custom 404 page, because none of those read a file outside the intended root. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.fprule.error_page_echo_is_not_a_file_read) states the full boundary.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
-- To decide this case, observe: load twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory. The bypass is proven when the encoded form returns a file body the literal form is rejected from, because characters other than the reserved set are equivalent
+- To decide this case, observe: Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.bypass.percent_encoding_normalization_defeats_allowlist) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013>
-- To decide this case, observe: when it is not. Replace the calibration probe with a path that exists only on the filesystem, and confirm it reads back only when the disk branch is live. Prefer a harmless marker file over a credential or key so the validation leaves no secret in the scan log, and re-run the identical request to show the effect is reproducible.
+- To decide this case, observe: A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.validation.disk_only_file_probe) states the full boundary.
   - Sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities>
 
 ## Validation bar (how to prove it)
 
+- Behaviour on a static-file prefix says nothing about a parameterised download handler, and the reverse holds too - each endpoint needs its own probe because the two are served by different code entirely.
+  - **Disproof:** The claim is false when both surfaces are served by the same confined component - a single static-file handler in front of every asset class, or a CDN or object-store gateway that applies one prefix rule to all buckets - in which case the static route's behaviour is genuinely informative about the download route. It also fails when the static surface is served by the web server itself from a document root, since the server's own path handling is a separate implementation and equally consistent across every alias it serves. And a specific finding on either endpoint still stands on its own evidence; this rule is only about the transfer of conclusions between endpoints.
+  - Sources: <https://docs.djangoproject.com/en/5.0/howto/static-files/> · <https://werkzeug.palletsprojects.com/en/stable/utils/>
 - Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.
   - **Disproof:** If a file that exists only on disk returns 404 or an error while the bundled asset returns 200, the read comes from the classpath and the finding is not actionable on that host.
   - Sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities>
 
 ## False-positive rules (when to reject it)
 
+- A response whose echoed path has ./ and ../ components stripped is consistent with normalisation by the client, the server, the framework, or the terminal - it does not by itself evidence an input filter, and it is not proof the traversal failed either.
+  - **Disproof:** The claim is false when the normalisation is provably server-side and effective - you can show the request as received by the origin, for example through a request log or a reflected value that only the server could have computed, and the traversal payload in that same form still fails, which is a genuine control. It is also false where the client is not in the picture at all: a request made from a script with a raw socket, a binary body carrying the path, or a file upload field bypasses any browser canonicalisation, so evidence from that channel is not subject to this ambiguity. And a genuinely successful read is a finding regardless of how many stages normalised the string on the way in, because the read happened.
+  - Sources: <https://man7.org/linux/man-pages/man2/open.2.html> · <https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html>
+- A file-serving helper whose first argument is documented as a trusted path is not a traversal candidate, because nothing in that signature claims the caller controls it - the bug is at the call site, not in the helper. _(unverified)_
+  - **Disproof:** The claim is false when the helper is nonetheless reached with attacker-controlled data - a handler that does new = send_file(request.args['name']) has the vulnerability regardless of what the documentation says, and the report is correct even though the blame is shared. It is also false when the path is trusted but the file it points to is not, which is a distinct and very productive finding: an attacker who can create a symlink or an archive entry inside a trusted directory escapes the directory without any traversal string at all, so no amount of argument validation would have helped. And the rule does not apply to the confined function: send_from_directory's safe_join behaviour and its 404 for a path that does not point to an existing regular file are the control, and an endpoint using it is not a traversal candidate on the argument alone.
+  - Sources: <https://werkzeug.palletsprojects.com/en/stable/utils/> · <https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html>
 - A filename you supplied appearing in a traversal error page or a session cookie is not a file read; the finding needs file CONTENT returned as the response body. _(unverified)_
   - **Disproof:** If the same route serves a fixed placeholder body for every nonexistent path including your traversal form, the identical-response rule applies and the report is a false positive; if any one form returns real file bytes, the finding is real regardless of what the other forms did.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
@@ -138,8 +189,26 @@
   - **Disproof:** If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The finding survives when the response body contains data from the targeted file and that content differs from anything served by the same route with a legitimate name.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (path_traversal.fprule.error_page_echo_is_not_a_file_read) states the full boundary.
+  - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
+
+## Impact framing
+
+- An LFI sink is an execution primitive rather than a read primitive, so the moment it can be pointed at a file the tester controls the included content runs with the web server's privileges.
+  - **Disproof:** Refuted if the sink returns the uploaded file's content as inert data without executing, for example because the include is downgraded to a read or the file's extension is never interpreted.
+  - Sources: <https://man7.org/linux/man-pages/man2/open.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md>
... (truncated)
```

## 2026-10-04 00:43 — 346 diff lines
- items: 56 (supported 25), FP rules 2, chains 1, state mature

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -20,198 +20,210 @@
 
 ## Prerequisites (do not start without these)
 
-- The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.
+- Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if /proc/<pid>/cmdline reads come back empty or error out through an LFI sink that successfully returns other known local files, showing the file inclusion cannot enumerate process metadata.
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md>
+- The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the chain still reaches execution on a host with allow_url_fopen=Off, or on a host with no path-disclosure primitive, or where the sink refuses paths inside the temp directory.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md>
-- Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.
-  - **Disproof:** Refuted if /proc/<pid>/cmdline reads come back empty or error out through an LFI sink that successfully returns other known local files, showing the file inclusion cannot enumerate process metadata.
-  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md>
-- Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.
+- Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
+  - Sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
+- Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a target whose ini shows allow_url_include=On rejects a remote URL supplied to the include parameter, or if a target with allow_url_include=Off happily includes one.
   - Sources: <https://docs.djangoproject.com/en/5.0/howto/static-files/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md>
-- Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.
-  - **Disproof:** If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
-  - Sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
 
 ## Recon signals (where to look)
 
-- On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.
+- On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the listing appears for a path that contains no traversal payload at all, or if the response for a non-existent path is identical to the response for the traversal path.
   - Sources: <https://docs.djangoproject.com/en/5.0/howto/static-files/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md>
-- The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.
+- The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the file inclusion succeeds repeatedly while the temp directory is non-writable and open_basedir is active, or if the disclosure output is clearly buffered yet the path still arrives at the tester.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md>
 
 ## Techniques (what to change)
 
-- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- This could allow an attacker to upload any executable file or other file with malicious code. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This could allow an attacker to upload any executable file or other file with malicious co".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The path is checked against an expected directory (/home/cwe/documents); otherwise, an att".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since the code does not check the filename that is provided in the header, an attacker can".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: library file sends a redirect if it is directly requested but continues to execute,".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Notice how this code also contains an error message information leak ( CWE-209 ) if the user parameter does not produce a file that exists: the full pathname is provided. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Notice how this code also contains an error message information leak ( CWE-209 ) if the us".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the targeted file is used for a security mechanism, then the attacker may be able to by".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
-- If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If errors must be captured in some detail, record them in log messages, but consider what ".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- The attacker may be able read the contents of unexpected files and expose sensitive data. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker may be able read the contents of unexpected files and expose sensitive data.".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
-- Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the file path should be validated and restricted to a specific directory to preve".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file ( CWE-306 ), then uses .. path traversal sequences ( CWE-23 ) in the file to access unexpected files, as exploited in the wild per CISA KEV. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: Cloud computing virtualization platform does not require authentication for upload ".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to apply to a wider range of files. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In many programming languages, the injection of a null byte (the 0 or NUL) may allow an at".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Chain: external control of values for user's desired language and theme enables path traversal. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: external control of values for user's desired language and theme enables path trave".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the path is not validated or modified to prevent it from containing relative or a".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With this version of the script, if the current working directory is /home/cwe/documents, ".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By using special elements such as ".." and "/" separators, attackers can escape outside of".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal> · <https://portswigger.net/web-security/file-path-traversal>
-- However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if the user supplies an absolute path, the os.path.join() function will discard t".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Bulletin board allows attackers to determine the existence of files using the avatar. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Bulletin board allows attackers to determine the existence of files using the avatar.".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- This may prevent the product from working at all and in the case of protection mechanisms such as authentication, it has the potential to lock out product users. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may prevent the product from working at all and in the case of protection mechanisms ".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Otherwise, store them in a separate directory and use the web server's access control capa".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if the current working directory is /home/user/documents, but the user inputs".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- This can give attackers enough room to bypass the intended validation. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
-- For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if an attacker provides ../../../../etc/passwd as input, the script will fetc".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- For example, appending a new account at the end of a password file may allow an attacker to bypass authentication. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, appending a new account at the end of a password file may allow an attacker t".
-  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
-- Ideally, the path should be resolved relative to some kind of application or user home directory. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the path should be resolved relative to some kind of application or user home dir".
... (truncated)
```

## 2026-10-04 00:50 — 16 diff lines
- items: 56 (supported 25), FP rules 2, chains 1, state mature

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -213,10 +213,9 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Fuzz the parameter with ../ sequences and an absolute /etc/passwd or a Windows win.ini, comparing body length against the baseline.
+2. Then try double-encoding (%252e%252e%252f) and ....//// to reach a filter that decodes once.
+3. Confirm the response contains file CONTENT, not a 200 status page.
 
 ### What counts as proof
 
```

## 2026-10-04 17:05 — 30 diff lines
- items: 58 (supported 27), FP rules 4, chains 1, state mature

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-22 · OWASP A01:2021
-> evidence: 56 items, 25 supported, 2 FP rules, 1 chains
+> evidence: 58 items, 27 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 A filename or path built from user input escapes its intended directory.
@@ -179,12 +179,18 @@
 - A filename you supplied appearing in a traversal error page or a session cookie is not a file read; the finding needs file CONTENT returned as the response body.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the same route serves a fixed placeholder body for every nonexistent path including your traversal form, the identical-response rule applies and the report is a false positive; if any one form returns real file bytes, the finding is real regardless of what the other forms did.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
+- A filename=../../../etc/passwd payload sent in a URL path segment or a multipart/form-data filename that the front-end web server removes before the application sees it is not path traversal, because the ../ sequence that would escape the base directory is neutralised upstream of the filesystem call and the read resolves inside the intended directory.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The rule stops being true when a context exists in which the sequence is not stripped — a query-string or JSON body parameter, a header such as X-Forwarded-Prefix, a filename that arrives base64- or multipart-encoded and is decoded by application code, or a second proxy hop that does not normalise — because then ../ does reach the pathname constructor and the resolved path leaves the restricted directory, which is exactly the CWE-22 condition.
+  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
 - A response whose echoed path has ./ and ../ components stripped is consistent with normalisation by the client, the server, the framework, or the terminal - it does not by itself evidence an input filter, and it is not proof the traversal failed either.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the normalisation is provably server-side and effective - you can show the request as received by the origin, for example through a request log or a reflected value that only the server could have computed, and the traversal payload in that same form still fails, which is a genuine control. It is also false where the client is not in the picture at all: a request made from a script with a raw socket, a binary body carrying the path, or a file upload field bypasses any browser canonicalisation, so evidence from that channel is not subject to this ambiguity. And a genuinely successful read is a finding regardless of how many stages normalised the string on the way in, because the read happened.
   - Sources: <https://man7.org/linux/man-pages/man2/open.2.html> · <https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html>
 - A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013> · <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
+- A user-supplied filename joined to a base directory and then canonicalised with a platform API (realpath, Path.getCanonicalPath, GetFullPath, abs_path) whose result still begins with the expected base directory is not path traversal, because canonicalisation resolves the .. segments and symlinks and the read stays inside the restricted directory the check named.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The rule is wrong when canonicalisation happens before validation rather than after (encoding introduced after the check), when the prefix test is a bare string compare so that /var/www/images_evil passes a check against /var/www/images, when the canonical base itself is attacker-influenced (a symlinked upload directory or a user-supplied base), when a TOCTOU swap replaces the validated path component before the open, or when the sink is not the filesystem but a shell, an include statement or an archive extractor that re-interprets the un-canonicalised string.
+  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://portswigger.net/web-security/file-path-traversal>
 
 ## Evidence requirements
 
```
