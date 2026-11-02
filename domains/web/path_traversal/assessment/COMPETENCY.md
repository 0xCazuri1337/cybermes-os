# Methodology — Path Traversal / File Inclusion

> Derived from 44 verified items. Regenerate with `python -m wks.methodgen --class path_traversal --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**This could allow an attacker to upload any executable file or other file with malicious code.**

())!=null; ) { if (line.indexOf(boundary) == -1) { bw.write(line); bw.newLine(); bw.flush(); } } //end of for loop bw.close(); 
 
 
 } catch (IOException ex) {...} // output successful upload response HTML page 
 } // output unsuccessful upload response HTML page else {...} 
 } ... 
 
 } 
 
 
 
 
 
 
 
 
 
 
 
 This code does not perform a check on the type of the file being uploaded ( CWE-434 ). This could allow an attacker to upload any executable file or other file with malicious code. 
 
 
 
 
 Additionally, the creation of the BufferedWriter object is subject to relative path traversal ( CWE-23 ). Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. Depending on the executing environment, the attacker may be able to specify arbitrary files to write to, leading to a w

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This could allow an attacker to upload any executable file or other file with ma”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory.**

} // output unsuccessful upload response HTML page else {...} 
 } ... 
 
 } 
 
 
 
 
 
 
 
 
 
 
 
 This code does not perform a check on the type of the file being uploaded ( CWE-434 ). This could allow an attacker to upload any executable file or other file with malicious code. 
 
 
 
 
 Additionally, the creation of the BufferedWriter object is subject to relative path traversal ( CWE-23 ). Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. Depending on the executing environment, the attacker may be able to specify arbitrary files to write to, leading to a wide variety of consequences, from code execution, XSS ( CWE-79 ), or system crash. 
 
 
 
 
 
 
 Example 6 
 
 
 This script intends to read a user-supplied file from the current directory. The user inputs the relative path to the file and the script uses Python's os.path.join()

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Since the code does not check the filename that is provided in the header, an at”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

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

**Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal.**

o the include() function. 
 
 
 
 
 
 
 
 CVE-2010-0012 
 
 
 
 
 Overwrite of files using a .. in a Torrent file. 
 
 
 
 
 
 
 
 CVE-2010-0013 
 
 
 
 
 Chat program allows overwriting files using a custom smiley request. 
 
 
 
 
 
 
 
 CVE-2008-5748 
 
 
 
 
 Chain: external control of values for user's desired language and theme enables path traversal. 
 
 
 
 
 
 
 
 CVE-2009-1936 
 
 
 
 
 Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 Resultant 
 
 
 
 (where the weakness is typically related to the presence of some other weaknesses)
 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Detection
 Methods 
 
 
 
 
 
 Method 
 Details 
 
 
 
 
 
 A

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: library file sends a redirect if it is directly requested but continues t”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

**Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access.**

User-controlled input 
 echo file_get_contents($filename); // Read and display the file contents 
 
 
 
 
 
 
 
 
 
 
 
 
 An attacker could manipulate the file path using relative (../) or absolute paths, potentially accessing sensitive system files. For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file. Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access. 
 
 
 
 
 
 
 
 
 (good code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 
 $allowed_files = [ 
 
 'readme' => 'public_files/readme.txt', 
 'terms' => 'public_files/terms.txt', 
 
 ]; 
 $key = $_GET['file'] ?? ''; 
 if (!isset($allowed_files[$key])) { 
 
 http_response_code(404); 
 exit('File not found.'); 
 
 } 
 $filepath = __DIR__ . '/' . $allowed_files[$key]; 
 if (!is_file($filepath) || !is_read

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, the file path should be validated and restricted to a specific director”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

**Chain: external control of values for user's desired language and theme enables path traversal.**

g the avatar. 
 
 
 
 
 
 
 
 CVE-2009-4581 
 
 
 
 
 PHP program allows arbitrary code execution using ".." in filenames that are fed to the include() function. 
 
 
 
 
 
 
 
 CVE-2010-0012 
 
 
 
 
 Overwrite of files using a .. in a Torrent file. 
 
 
 
 
 
 
 
 CVE-2010-0013 
 
 
 
 
 Chat program allows overwriting files using a custom smiley request. 
 
 
 
 
 
 
 
 CVE-2008-5748 
 
 
 
 
 Chain: external control of values for user's desired language and theme enables path traversal. 
 
 
 
 
 
 
 
 CVE-2009-1936 
 
 
 
 
 Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 Resultant

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: external control of values for user's desired language and theme enables ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**Bulletin board allows attackers to determine the existence of files using the avatar.**

reation of arbitrary directories using ".." in the MKD command. 
 
 
 
 
 
 
 
 CVE-2009-0244 
 
 
 
 
 FTP service for a Bluetooth device allows listing of directories, and creation or reading of files using ".." sequences. 
 
 
 
 
 
 
 
 CVE-2009-4013 
 
 
 
 
 Software package maintenance program allows overwriting arbitrary files using "../" sequences. 
 
 
 
 
 
 
 
 CVE-2009-4449 
 
 
 
 
 Bulletin board allows attackers to determine the existence of files using the avatar. 
 
 
 
 
 
 
 
 CVE-2009-4581 
 
 
 
 
 PHP program allows arbitrary code execution using ".." in filenames that are fed to the include() function. 
 
 
 
 
 
 
 
 CVE-2010-0012 
 
 
 
 
 Overwrite of files using a .. in a Torrent file. 
 
 
 
 
 
 
 
 CVE-2010-0013 
 
 
 
 
 Chat program allows overwriting files using a custom smiley request. 
 
 
 
 
 
 
 
 CVE-2008-5748 
 
 
 
 
 Chain: extern

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Bulletin board allows attackers to determine the existence of files using the av”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

**For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file.**

presents the contents back to the caller. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 
 $filename = $_GET['file']; // User-controlled input 
 echo file_get_contents($filename); // Read and display the file contents 
 
 
 
 
 
 
 
 
 
 
 
 
 An attacker could manipulate the file path using relative (../) or absolute paths, potentially accessing sensitive system files. For example, if an attacker provides ../../../../etc/passwd as input, the script will fetch and display the contents of the system's password file. Ideally, the file path should be validated and restricted to a specific directory to prevent unauthorized file access. 
 
 
 
 
 
 
 
 
 (good code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 
 $allowed_files = [ 
 
 'readme' => 'public_files/readme.txt', 
 'terms' => 'public_files/terms.txt', 
 
 ]; 
 $key = $_GET['file'] ?? ''; 
 if (!isset($allowed_files[$key])) { 
 
 http_response_code(404); 
 e

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, if an attacker provides ../../../../etc/passwd as input, the script”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism.**

ommands 
 
 
 
 
 
 
 Scope: Integrity, Confidentiality, Availability 
 
 
 
 The attacker may be able to create or overwrite critical files that are used to execute code, such as programs or libraries. 
 
 
 
 
 
 
 
 
 Modify Files or Directories 
 
 
 
 
 
 
 Scope: Integrity 
 
 
 
 The attacker may be able to overwrite or create critical files, such as programs, libraries, or important data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, appending a new account at the end of a password file may allow an attacker to bypass authentication. 
 
 
 
 
 
 
 
 
 Read Files or Directories 
 
 
 
 
 
 
 Scope: Confidentiality 
 
 
 
 The attacker may be able read the contents of unexpected files and expose sensitive data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mecha

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If the targeted file is used for a security mechanism, then the attacker may be ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**The attacker may be able read the contents of unexpected files and expose sensitive data.**

overwrite or create critical files, such as programs, libraries, or important data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, appending a new account at the end of a password file may allow an attacker to bypass authentication. 
 
 
 
 
 
 
 
 
 Read Files or Directories 
 
 
 
 
 
 
 Scope: Confidentiality 
 
 
 
 The attacker may be able read the contents of unexpected files and expose sensitive data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, by reading a password file, the attacker could conduct brute force password guessing attacks in order to break into an account on the system. 
 
 
 
 
 
 
 
 
 DoS: Crash, Exit, or Restart 
 
 
 
 
 
 
 Scope: Availability 
 
 
 
 The attacker may be able to overwrite, delet

- *Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The attacker may be able read the contents of unexpected files and expose sensit”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system.**

irectory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory. 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Extended Description
 
 
 
 
 
 Many file operations are intended to take place within a restricted directory. By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the "../" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as "/usr/local/bin" to access unexpected files. This is referred to as absolute path traversal.

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“By using special elements such as ".." and "/" separators, attackers can escape ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**

chances of success. 
 If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. Highly sensitive information such as passwords should never be saved to log files. 
 Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a user account exists or not. 
 In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. 
 
 
 
 
 
 
 
 
 
 
 Operation; Implementation 
 
 
 
 
 
 
 Strategy: Environment Hardening 
 
 
 When using PHP, configure the application so that it does not use register_globals. During implementation, develop the application so that it does not rely on this feature, but be wary of implementing a register_globals emulation that is subject to weaknesses such as CWE-95 , CWE-621 , and similar

- *Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In the context of path traversal, error messages which disclose path information”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

**The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ).**

d() 
 
 
 except FileNotFoundError as e: 
 
 print("Error - file not found") 
 
 
 
 main()
 
 
 
 
 
 
 
 
 
 
 
 
 The constructed path string uses os.sep to add the appropriate separation character for the given operating system (e.g. '\' or '/') and the call to os.path.normpath() removes any additional slashes that may have been entered - this may occur particularly when using a Windows path. The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ). By putting the pieces of the path string together in this fashion, the script avoids a call to os.path.join() and any potential issues that might arise if an absolute path is entered. With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd. The user is therefore contained w

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The path is checked against an expected directory (/home/cwe/documents); otherwi”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file ( CWE-306 ), then uses .. path traversal sequences ( CWE-23 ) in the file to access unexpected files, as exploited in the wild per CISA KEV.**

path.join call on untrusted input, allowing absolute path traversal because os.path.join resets the pathname to an absolute path that is specified as part of the input. 
 
 
 
 
 
 
 
 CVE-2022-24877 
 
 
 
 
 directory traversal in Go-based Kubernetes operator app allows accessing data from the controller's pod file system via ../ sequences in a yaml file 
 
 
 
 
 
 
 
 CVE-2021-21972 
 
 
 
 
 Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file ( CWE-306 ), then uses .. path traversal sequences ( CWE-23 ) in the file to access unexpected files, as exploited in the wild per CISA KEV. 
 
 
 
 
 
 
 
 CVE-2020-4053 
 
 
 
 
 a Kubernetes package manager written in Go allows malicious plugins to inject path traversal sequences into a plugin archive ("Zip slip") to copy a file outside the intended directory 
 
 
 
 
 
 
 
 CVE-2020-3452 
 
 
 
 
 Chain: security product has improper input validation ( CWE-20 ) leading to directory traversal ( CWE-22 ), as exploited in the wild pe

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chain: Cloud computing virtualization platform does not require authentication f”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to apply to a wider range of files.**

variant is affected. For example, a researcher might say that "..\" is vulnerable, but not test "../" which may also be vulnerable. 
 Any combination of directory separators ("/", "\", etc.) and numbers of "." (e.g. "....") can produce unique variants; for example, the "//../" variant is not listed (CVE-2004-0325). See this entry's children and lower-level descendants. 
 
 
 
 
 
 
 
 
 Other 
 
 In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to apply to a wider range of files. For example, the product may add ".txt" to any pathname, thus limiting the attacker to text files, but a null injection may effectively remove this restriction.
 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 Taxonomy
 Mappings 
 
 
 
 
 
 
 Mapped Taxonomy Name 
 Node ID 
 Fit 
 Mapped Node Name 
 
 
 
 
 PLOVER 
 
 
 Path Traversal 
 
 
 
 OWASP Top Ten 2007 
 A4 
 CWE More Specific 
 Insecure Direct Object R

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In many programming languages, the injection of a null byte (the 0 or NUL) may a”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object.**

de would need to be examined. 
 
 
 
 
 
 
 Example 2 
 
 
 In the example below, the path to a dictionary file is read from a system property and used to initialize a File object. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: Java 
 
 
 
 
 
 String filename = System.getProperty("com.domain.application.dictionaryFile"); File dictionaryFile = new File(filename); 
 
 
 
 
 
 
 
 
 
 
 
 However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object. This allows anyone who can control the system property to determine what file is used. Ideally, the path should be resolved relative to some kind of application or user home directory. 
 
 
 
 
 
 
 Example 3 
 
 
 The following code takes untrusted input and uses a regular expression to filter "../" from the input. It then appends this result to the /home/user/ directory and attempts to read the

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, the path is not validated or modified to prevent it from containing rel”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd.**

d against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ). By putting the pieces of the path string together in this fashion, the script avoids a call to os.path.join() and any potential issues that might arise if an absolute path is entered. With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd. The user is therefore contained within the current working directory as intended. 
 
 
 
 
 
 
 Example 7 
 
 
 This PHP code takes user input in a file argument, obtains its contents, and presents the contents back to the caller. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 
 $filename = $_GET['file']; // User-controlled input 
 echo file_get_contents($filename); // R

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“With this version of the script, if the current working directory is /home/cwe/d”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

**However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided.**

d it, an error is printed to the user. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: Python 
 
 
 
 
 
 
 import os 
 import sys 
 def main(): 
 
 filename = sys.argv[1] 
 path = os.path.join(os.getcwd(), filename) 
 try: 
 
 with open(path, 'r') as f: 
 
 file_data = f.read() 
 
 
 except FileNotFoundError as e: 
 
 print("Error - file not found") 
 
 
 main()
 
 
 
 
 
 
 
 
 
 
 
 
 However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided. For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path. In the above scenario, this would cause the script to access and read the /etc/passwd file. 
 
 
 
 
 
 
 
 
 (good code) 
 
 
 Example Language: Python 
 
 
 
 
 
 
 import os 
 import sys 
 def main(): 
 
 filenam

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, if the user supplies an absolute path, the os.path.join() function will”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path.**

.argv[1] 
 path = os.path.join(os.getcwd(), filename) 
 try: 
 
 with open(path, 'r') as f: 
 
 file_data = f.read() 
 
 
 except FileNotFoundError as e: 
 
 print("Error - file not found") 
 
 
 main()
 
 
 
 
 
 
 
 
 
 
 
 
 However, if the user supplies an absolute path, the os.path.join() function will discard the path to the current working directory and use only the absolute path provided. For example, if the current working directory is /home/user/documents, but the user inputs /etc/passwd, os.path.join() will use only /etc/passwd, as it is considered an absolute path. In the above scenario, this would cause the script to access and read the /etc/passwd file. 
 
 
 
 
 
 
 
 
 (good code) 
 
 
 Example Language: Python 
 
 
 
 
 
 
 import os 
 import sys 
 def main(): 
 
 filename = sys.argv[1] 
 path = os.path.normpath(f"{os.getcwd()}{os.sep}{filename}") 
 if path.startswith("/home/cwe/documents/"): 
 
 try: 
 
 with open(path, 'r') as f: 
 
 file_data = f.re

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, if the current working directory is /home/user/documents, but the u”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

**Ideally, the path should be resolved relative to some kind of application or user home directory.**

age: Java 
 
 
 
 
 
 String filename = System.getProperty("com.domain.application.dictionaryFile"); File dictionaryFile = new File(filename); 
 
 
 
 
 
 
 
 
 
 
 
 However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object. This allows anyone who can control the system property to determine what file is used. Ideally, the path should be resolved relative to some kind of application or user home directory. 
 
 
 
 
 
 
 Example 3 
 
 
 The following code takes untrusted input and uses a regular expression to filter "../" from the input. It then appends this result to the /home/user/ directory and attempts to read the file in the final resulting path. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: Perl 
 
 
 
 
 
 my $Username = GetUntrustedInput(); $Username =~ s/\.\.\///; my $filename =

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ideally, the path should be resolved relative to some kind of application or use”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [owasp.org](https://owasp.org/www-community/attacks/Path_Traversal)

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

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A filename=../../../etc/passwd payload sent in a URL path segment or a multipart/form-data filename that the front-end web server removes before the application sees it is not path traversal, because the ../ sequence that would escape the base directory is neutralised upstream of the filesystem call and the read resolves inside the intended directory.**

Mechanism: CWE-22 requires the special element to survive into the pathname the product constructs; in the common deployment the HTTP layer (front proxy, servlet container, or the framework's own multipart parser) collapses or strips ../ in the request path and in the uploaded filename before application code builds the file path, so new File(base, userInput) or fopen() receives a name with the traversal already gone and reads a sibling inside the base directory (often a 404). The check that separates the two cases is to observe what the handler received, not what was transmitted: compare the raw request bytes with the value logged/echoed by the application, or re-issue the payload double-encoded (%252e%252e%252f) and through a non-stripped context such as a query parameter. If the payload only changes behaviour when a second decode reintroduces the sequence, the finding is about decoding/normalisation order, not about a reachable ../ in the pathname.

- *Disproof:* The rule stops being true when a context exists in which the sequence is not stripped — a query-string or JSON body parameter, a header such as X-Forwarded-Prefix, a filename that arrives base64- or multipart-encoded and is decoded by application code, or a second proxy hop that does not normalise — because then ../ does reach the pathname constructor and the resolved path leaves the restricted directory, which is exactly the CWE-22 condition.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

**A user-supplied filename joined to a base directory and then canonicalised with a platform API (realpath, Path.getCanonicalPath, GetFullPath, abs_path) whose result still begins with the expected base directory is not path traversal, because canonicalisation resolves the .. segments and symlinks and the read stays inside the restricted directory the check named.**

Mechanism: the containment test is applied to the canonical path, not to the raw string, so ../../etc/passwd collapses to <base>/etc/passwd and passes the startsWith(BASE_DIRECTORY) prefix test while a sibling directory that merely shares the base prefix (/var/www/images_evil) does not. The check that distinguishes false from true positives is therefore: canonicalise first, then compare the canonical result against the canonical base with a separator-aware prefix test, and confirm the file actually returned belongs to the base subtree. A scanner that flags every request containing ../ misses the point of the rule — the finding is false whenever the file served is inside the allowed directory, and the residual issue is only that error messages may disclose paths. The same rule explains why an absolute-path attempt (/etc/passwd) that the join collapses back under the base is also not traversal.

- *Disproof:* The rule is wrong when canonicalisation happens before validation rather than after (encoding introduced after the check), when the prefix test is a bare string compare so that /var/www/images_evil passes a check against /var/www/images, when the canonical base itself is attacker-influenced (a symlinked upload directory or a user-supplied base), when a TOCTOU swap replaces the validated path component before the open, or when the sink is not the filesystem but a shell, an include statement or an archive extractor that re-interprets the un-canonicalised string.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/22.html); [portswigger.net](https://portswigger.net/web-security/file-path-traversal)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Path traversal payloads are typically obfuscated to defeat simple filters: URL encoding (%2e%2e%2f), double URL encoding (%252e%252e%252f), partial encoding (..%2f), null-byte termination (%00 on legacy PHP < 5.3.4), and filter bypasses such as '....//' that survive non-recursive replacement.**

Filters that naively strip '../' are defeated by: (1) URL-encoding dots and slashes as %2e%2e%2f; (2) double-encoding as %252e%252e%252f so one decode round leaves the payload intact; (3) mixing encoded and raw characters such as ..%2f; (4) null-byte injection (%00) that truncates the string at the OS level, bypassing extension validation such as '../../../etc/passwd%00.jpg'; (5) '....//', which after one pass of '../' removal still yields '../'; and (6) backslashes on Windows ('..\\'), which many naive filters treat as directory separators only on Windows. AVDS web-app pentesting playbooks and HackTricks enumerate these bypass classes as the standard probe progression.

- *Disproof:* Canonicalize the path with realpath/getCanonicalPath/Path.resolve to an absolute path that collapses all encoding variants, then assert containment with a separator-aware comparison; reject null bytes, backslashes, and absolute-path markers as a defense-in-depth layer.
- *Evidence:* high_confidence — [desecurity.github.io](https://desecurity.github.io/hacktricks/pentesting-web/file-inclusion/); [eligof.github.io](https://eligof.github.io/Web-App-Pentesting-Playbook/vulns/path-traversal.html); [enriquefolte.com](https://enriquefolte.com/manual/03_Exploitation/Web_Exploitation/LFI_Path_Traversal_Bypasses)

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

**Path traversal enables reading arbitrary files (confidentiality breach), and where the vulnerable input flows into a file include/execute primitive (PHP include, LFI, JSP/SQL), it enables code execution via log poisoning, wrapper protocols, or upload of a webshell.**

Impact is driven by the files targeted: /etc/passwd and /etc/shadow expose credentials enabling brute-force password guessing or privilege escalation; application configuration files (web.config, .env, app.properties) disclose database credentials and API keys; and source code exposes business logic and further secrets. Where the vulnerable input flows into a file include or execute primitive (PHP include($_GET['page']), LFI), an attacker can chain local file inclusion with log poisoning or wrapper protocols (php://filter, php://input) to achieve remote code execution. CVE-2019-19781 (Citrix ADC/Gateway, CVSS 9.8) allowed traversal to arbitrary files and script planting; CVE-2021-41773 (Apache HTTP Server 2.4.49) allowed mapping URLs outside the document root, and CVE-2021-42013 turned it into RCE with CGI enabled. NIST NVD rates path traversal CVEs up to CVSS 10.0, and CISA reported active exploitation of tens of thousands of Citrix appliances before patching.

- *Disproof:* Run the serving process with the minimum filesystem permissions needed so even a successful traversal reaches only files the process account can read; serve files through an allowlist; replace raw paths with server-side identifiers.
- *Evidence:* high_confidence — [community.owasp.org](https://community.owasp.org/attacks/Path_Traversal); [cwe.mitre.org](https://cwe.mitre.org/data/published/cwe_latest.pdf); [safeguard.sh](https://safeguard.sh/resources/blog/what-is-path-traversal)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
