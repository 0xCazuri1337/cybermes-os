# Path Traversal / File Inclusion

## Definition

A filename or path built from user input escapes its intended directory.

- **CWE:** CWE-22
- **OWASP:** A01:2021
- **Surface:** web
- **Aliases:** ["path traversal", "directory traversal", "lfi", "rfi", "file inclusion"]

Canonical home for `path_traversal`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.**

The chain is gated on three conditions that must hold together: the nested remote fetch needs allow_url_fopen=On, the LFI sink must be permitted to include from the writable temp directory, and a path-disclosure primitive must reveal the live temp file name.

HackTricks reference: LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure (pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

*Disproof:* Refuted if the chain still reaches execution on a host with allow_url_fopen=Off, or on a host with no path-disclosure primitive, or where the sink refuses paths inside the temp directory.

**Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.**

Before any temp-path brute force through an LFI sink, the tester must confirm the traversal reaches /proc at all, by walking /proc/<pid>/cmdline through the inclusion until worker-process strings show up.

HackTricks reference: LFI2RCE via Nginx temp files (pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

*Disproof:* Refuted if /proc/<pid>/cmdline reads come back empty or error out through an LFI sink that successfully returns other known local files, showing the file inclusion cannot enumerate process metadata.

**Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.**

Whether remote inclusion is even possible on a PHP target is decided by ini switches with different defaults, so every candidate LFI sink must be classified by which of allow_url_include and allow_url_fopen is actually on before it is called exploitable.

HackTricks reference: File Inclusion/Path traversal (pentesting-web/file-inclusion/README.md)

*Disproof:* Refuted if a target whose ini shows allow_url_include=On rejects a remote URL supplied to the include parameter, or if a target with allow_url_include=Off happily includes one.

**Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.**

Locate the concatenation first: static file handlers, error-page renderers and template loaders that build base plus userValue are the recurring shape. Then confirm the sink actually opens that path and streams the contents back, rather than resolving it against a classpath or resource namespace where the traversal is inert. Probe with a segment count that must exceed the depth of the base directory, and check the response body for content that could only come from outside the served root. Where the sink falls back to a classpath loader, treat a 200 as unproven until a disk-only file reads back.

*Disproof:* If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.**

On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.

HackTricks reference: File Inclusion/Path traversal (pentesting-web/file-inclusion/README.md)

*Disproof:* Refuted if the listing appears for a path that contains no traversal payload at all, or if the response for a non-existent path is identical to the response for the traversal path.

**The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.**

The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.

HackTricks reference: LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure (pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

*Disproof:* Refuted if the file inclusion succeeds repeatedly while the temp directory is non-writable and open_basedir is active, or if the disclosure output is clearly buffered yet the path still arrives at the tester.

**A convincing observation for this class is: The finding survives when the response body contains data from the targeted file and that content differs from anything served by the same route with a legitimate name.**

Derived from path_traversal.fprule.error_page_echo_is_not_a_file_read, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (path_traversal.fprule.error_page_echo_is_not_a_file_read) states the full boundary.

## Exploitation

**In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**

chances of success. 
 If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. Highly sensitive information such as passwords should never be saved to log files. 
 Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a user account exists or not. 
 In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. 
 
 
 
 
 
 
 
 
 
 
 Operation; Implementation 
 
 
 
 
 
 
 Strategy: Environment Hardening 
 
 
 When using PHP, configure the application so that it does not use register_globals. During implementation, develop the application so that it does not rely on this feature, but be wary of implementing a register_globals emulation that is subject to weaknesses such as CWE-95 , CWE-621 , and similar

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".

**This could allow an attacker to upload any executable file or other file with malicious code.**

())!=null; ) { if (line.indexOf(boundary) == -1) { bw.write(line); bw.newLine(); bw.flush(); } } //end of for loop bw.close(); 
 
 
 } catch (IOException ex) {...} // output successful upload response HTML page 
 } // output unsuccessful upload response HTML page else {...} 
 } ... 
 
 } 
 
 
 
 
 
 
 
 
 
 
 
 This code does not perform a check on the type of the file being uploaded ( CWE-434 ). This could allow an attacker to upload any executable file or other file with malicious code. 
 
 
 
 
 Additionally, the creation of the BufferedWriter object is subject to relative path traversal ( CWE-23 ). Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. Depending on the executing environment, the attacker may be able to specify arbitrary files to write to, leading to a w

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This could allow an attacker to upload any executable file or other file with malicious co".

**The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ).**

d() 
 
 
 except FileNotFoundError as e: 
 
 print("Error - file not found") 
 
 
 
 main()
 
 
 
 
 
 
 
 
 
 
 
 
 The constructed path string uses os.sep to add the appropriate separation character for the given operating system (e.g. '\' or '/') and the call to os.path.normpath() removes any additional slashes that may have been entered - this may occur particularly when using a Windows path. The path is checked against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ). By putting the pieces of the path string together in this fashion, the script avoids a call to os.path.join() and any potential issues that might arise if an absolute path is entered. With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd. The user is therefore contained w

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The path is checked against an expected directory (/home/cwe/documents); otherwise, an att".

**The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.**

r example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. 
 This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject to compromise. 
 Be careful to avoid CWE-243 and other weaknesses related to jails. 
 
 
 
 Effectiveness: Limited 
 
 
 
 Note: 
 The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Attack Surface Reduction 
 
 
 
 Store library, include, and utility files outside of the web document root, if possible. Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them. One common practice is to define a fixed constant

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The effectiveness of this mitigation depends on the prevention capabilities of the specifi".

**Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory.**

} // output unsuccessful upload response HTML page else {...} 
 } ... 
 
 } 
 
 
 
 
 
 
 
 
 
 
 
 This code does not perform a check on the type of the file being uploaded ( CWE-434 ). This could allow an attacker to upload any executable file or other file with malicious code. 
 
 
 
 
 Additionally, the creation of the BufferedWriter object is subject to relative path traversal ( CWE-23 ). Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. Depending on the executing environment, the attacker may be able to specify arbitrary files to write to, leading to a wide variety of consequences, from code execution, XSS ( CWE-79 ), or system crash. 
 
 
 
 
 
 
 Example 6 
 
 
 This script intends to read a user-supplied file from the current directory. The user inputs the relative path to the file and the script uses Python's os.path.join()

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since the code does not check the filename that is provided in the header, an attacker can".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: library file sends a redirect if it is directly requested but continues to execute,".

**Notice how this code also contains an error message information leak ( CWE-209 ) if the user parameter does not produce a file that exists: the full pathname is provided.**

(result) 
 
 
  
 
 
 
 
 
 /users/cwe/profiles/../../../etc/passwd 
 
 
 
 
 
 
 
 
 
 
 
 When the file is opened, the operating system resolves the "../" during path canonicalization and actually accesses this file: 
 
 
 
 
 
 
 
 
 (result) 
 
 
  
 
 
 
 
 
 /etc/passwd 
 
 
 
 
 
 
 
 
 
 
 
 As a result, the attacker could read the entire text of the password file. 
 
 
 
 
 Notice how this code also contains an error message information leak ( CWE-209 ) if the user parameter does not produce a file that exists: the full pathname is provided. Because of the lack of output encoding of the file that is retrieved, there might also be a cross-site scripting problem ( CWE-79 ) if profile contains any HTML, but other code would need to be examined. 
 
 
 
 
 
 
 Example 2 
 
 
 In the example below, the path to a dictionary file is read from a system property and used to initialize a File object. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Examp

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Notice how this code also contains an error message information leak ( CWE-209 ) if the us".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the targeted file is used for a security mechanism, then the attacker may be able to by".

**If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers.**

ntended audience and no one else. The messages need to strike the balance between being too cryptic (which can confuse users) or being too detailed (which may reveal more than intended). The messages should not reveal the methods that were used to determine the error. Attackers can use detailed information to refine or optimize their original attack, thereby increasing their chances of success. 
 If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. Highly sensitive information such as passwords should never be saved to log files. 
 Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a user account exists or not. 
 In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hi

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If errors must be captured in some detail, record them in log messages, but consider what ".

**In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.**

chances of success. 
 If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. Highly sensitive information such as passwords should never be saved to log files. 
 Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a user account exists or not. 
 In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. 
 
 
 
 
 
 
 
 
 
 
 Operation; Implementation 
 
 
 
 
 
 
 Strategy: Environment Hardening 
 
 
 When using PHP, configure the application so that it does not use register_globals. During implementation, develop the application so that it does not rely on this feature, but be wary of implementing a register_globals emulation that is subject to weaknesses such as CWE-95 , CWE-621 , and similar

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".

**The attacker may be able read the contents of unexpected files and expose sensitive data.**

overwrite or create critical files, such as programs, libraries, or important data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, appending a new account at the end of a password file may allow an attacker to bypass authentication. 
 
 
 
 
 
 
 
 
 Read Files or Directories 
 
 
 
 
 
 
 Scope: Confidentiality 
 
 
 
 The attacker may be able read the contents of unexpected files and expose sensitive data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, by reading a password file, the attacker could conduct brute force password guessing attacks in order to break into an account on the system. 
 
 
 
 
 
 
 
 
 DoS: Crash, Exit, or Restart 
 
 
 
 
 
 
 Scope: Availability 
 
 
 
 The attacker may be able to overwrite, delet

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker may be able read the contents of unexpected files and expose sensitive data.".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the file path should be validated and restricted to a specific directory to preve".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: Cloud computing virtualization platform does not require authentication for upload ".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In many programming languages, the injection of a null byte (the 0 or NUL) may allow an at".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: external control of values for user's desired language and theme enables path trave".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the path is not validated or modified to prevent it from containing relative or a".

**With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd.**

d against an expected directory (/home/cwe/documents); otherwise, an attacker could provide relative path sequences like ".." to cause normpath() to generate paths that are outside the intended directory ( CWE-23 ). By putting the pieces of the path string together in this fashion, the script avoids a call to os.path.join() and any potential issues that might arise if an absolute path is entered. With this version of the script, if the current working directory is /home/cwe/documents, and the user inputs /etc/passwd, the resulting path will be /home/cwe/documents/etc/passwd. The user is therefore contained within the current working directory as intended. 
 
 
 
 
 
 
 Example 7 
 
 
 This PHP code takes user input in a file argument, obtains its contents, and presents the contents back to the caller. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: PHP 
 
 
 
 
 
 
 $filename = $_GET['file']; // User-controlled input 
 echo file_get_contents($filename); // R

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With this version of the script, if the current working directory is /home/cwe/documents, ".

**By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system.**

irectory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory. 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Extended Description
 
 
 
 
 
 Many file operations are intended to take place within a restricted directory. By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the "../" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as "/usr/local/bin" to access unexpected files. This is referred to as absolute path traversal.

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By using special elements such as ".." and "/" separators, attackers can escape outside of".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if the user supplies an absolute path, the os.path.join() function will discard t".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Bulletin board allows attackers to determine the existence of files using the avatar.".

**This may prevent the product from working at all and in the case of protection mechanisms such as authentication, it has the potential to lock out product users.**

bypass that mechanism. For example, by reading a password file, the attacker could conduct brute force password guessing attacks in order to break into an account on the system. 
 
 
 
 
 
 
 
 
 DoS: Crash, Exit, or Restart 
 
 
 
 
 
 
 Scope: Availability 
 
 
 
 The attacker may be able to overwrite, delete, or corrupt unexpected critical files such as programs, libraries, or important data. This may prevent the product from working at all and in the case of protection mechanisms such as authentication, it has the potential to lock out product users. 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Potential Mitigations 
 
 
 
 
 
 
 Phase(s) 
 Mitigation 
 
 
 
 
 
 
 
 Implementation 
 
 
 
 
 
 
 Strategy: Input Validation 
 
 
 
 Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This may prevent the product from working at all and in the case of protection mechanisms ".

**Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them.**

ndbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed. 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Attack Surface Reduction 
 
 
 
 Store library, include, and utility files outside of the web document root, if possible. Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them. One common practice is to define a fixed constant in each calling program, then check for the existence of the constant in the library/include file; if the constant does not exist, then the file was directly requested, and it can exit immediately. 
 This significantly reduces the chance of an attacker being able to bypass any protection mechanisms that are in the base program but not in the inclu

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Otherwise, store them in a separate directory and use the web server's access control capa".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if the current working directory is /home/user/documents, but the user inputs".

**This can give attackers enough room to bypass the intended validation.**

ness rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue." 
 Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright. 
 When validating filenames, use stringent allowlists that limit the character set to be used. If feasible, only allow a single "." character in the filename to avoid weaknesses such as CWE-23 , and exclude directory separators such as "/" to avoid C

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can give attackers enough room to bypass the intended validation.".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, if an attacker provides ../../../../etc/passwd as input, the script will fetc".

**For example, appending a new account at the end of a password file may allow an attacker to bypass authentication.**

e or overwrite critical files that are used to execute code, such as programs or libraries. 
 
 
 
 
 
 
 
 
 Modify Files or Directories 
 
 
 
 
 
 
 Scope: Integrity 
 
 
 
 The attacker may be able to overwrite or create critical files, such as programs, libraries, or important data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, appending a new account at the end of a password file may allow an attacker to bypass authentication. 
 
 
 
 
 
 
 
 
 Read Files or Directories 
 
 
 
 
 
 
 Scope: Confidentiality 
 
 
 
 The attacker may be able read the contents of unexpected files and expose sensitive data. If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism. For example, by reading a password file, the attacker could conduct brute force password guessing attacks in

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, appending a new account at the end of a password file may allow an attacker t".

**Ideally, the path should be resolved relative to some kind of application or user home directory.**

age: Java 
 
 
 
 
 
 String filename = System.getProperty("com.domain.application.dictionaryFile"); File dictionaryFile = new File(filename); 
 
 
 
 
 
 
 
 
 
 
 
 However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object. This allows anyone who can control the system property to determine what file is used. Ideally, the path should be resolved relative to some kind of application or user home directory. 
 
 
 
 
 
 
 Example 3 
 
 
 The following code takes untrusted input and uses a regular expression to filter "../" from the input. It then appends this result to the /home/user/ directory and attempts to read the file in the final resulting path. 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: Perl 
 
 
 
 
 
 my $Username = GetUntrustedInput(); $Username =~ s/\.\.\///; my $filename =

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, the path should be resolved relative to some kind of application or user home dir".

**That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.**

dify legitimate requests. Finally, some manual effort may be required for customization. 
 
 
 
 
 
 
 
 
 Architecture and Design; Operation 
 
 
 
 
 
 
 Strategy: Environment Hardening 
 
 
 Run your code using the lowest privileges that are required to accomplish the necessary tasks [ REF-76 ]. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations. 
 
 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 
 Strategy: Enforcement by Conversion 
 
 
 
 When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filen

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "That way, a successful attack will not immediately give the attacker access to the rest of".

**A directory listing from a traversal probe is only a map, not a result - the real file surface is reached by pushing the discovered folder name through the LFI sink and seeing whether it resolves to server-side files.**

A directory listing from a traversal probe is only a map, not a result - the real file surface is reached by pushing the discovered folder name through the LFI sink and seeing whether it resolves to server-side files.

HackTricks reference: File Inclusion/Path traversal (pentesting-web/file-inclusion/README.md)

*Disproof:* Refuted if the discovered folder name through the LFI sink errors out while other known local files resolve fine, or if the listing is a static client-side index that does not correspond to any server-side path.

**The in-flight request body is reachable through the process file-descriptor table, so once /proc walking yields fd paths, feeding those paths straight into the LFI parameter includes the buffered request bytes directly.**

The in-flight request body is reachable through the process file-descriptor table, so once /proc walking yields fd paths, feeding those paths straight into the LFI parameter includes the buffered request bytes directly.

HackTricks reference: LFI2RCE via Nginx temp files (pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

*Disproof:* Refuted if the discovered fd paths return empty or non-executable content through the sink, or return whatever file the descriptor points at rather than the buffered request body.

**Because the tester cannot predict the temporary filename, the practical approach is to hold an LFI request open indefinitely and brute-force candidate names inside that window, converting connection lifetime into a search budget.**

Because the tester cannot predict the temporary filename, the practical approach is to hold an LFI request open indefinitely and brute-force candidate names inside that window, converting connection lifetime into a search budget.

HackTricks reference: LFI2RCE via Eternal waiting (pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

*Disproof:* Refuted if the server or an intermediary aborts the long-lived request well before the candidate space is covered, or if the request terminates on the first miss instead of continuing through the list.

**Once the held-open behaviour is confirmed in the lab or on the target version, scattering thousands of timed-out uploads raises the odds that one of those candidates is caught by the LFI, using fewer long-lived connections than brute force would.**

Once the held-open behaviour is confirmed in the lab or on the target version, scattering thousands of timed-out uploads raises the odds that one of those candidates is caught by the LFI, using fewer long-lived connections than brute force would.

HackTricks reference: LFI2RCE via Eternal waiting (pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

*Disproof:* Refuted if the same held-open behaviour cannot be reproduced on the target version, or if repeated uploads leave nothing retrievable because cleanup deletes every candidate before the include lands.

**When an LFI sink targets the temporary backing file by its own local pathname, the file inclusion consumes the raw request body as written before the decompression wrapper runs, so a payload that only becomes valid after decompression will not execute.**

When an LFI sink targets the temporary backing file by its own local pathname, the file inclusion consumes the raw request body as written before the decompression wrapper runs, so a payload that only becomes valid after decompression will not execute.

HackTricks reference: LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure (pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md)

*Disproof:* Refuted if the same file inclusion executes a payload that is only well-formed after the decompression step, which would show the LFI consumed the decoded stream rather than the stored raw bytes.

**When a single temp file does not live long enough to be caught by the LFI, saturating the workers with concurrent requests widens the window so at least one buffered body file survives for the file inclusion to reach.**

When a single temp file does not live long enough to be caught by the LFI, saturating the workers with concurrent requests widens the window so at least one buffered body file survives for the file inclusion to reach.

HackTricks reference: LFI2RCE via Nginx temp files (pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md)

*Disproof:* Refuted if raising concurrency changes nothing about how often the fd-path file inclusion catches a temp file, or if the added load recycles workers so file lifetime shrinks rather than grows.

**Including an attacker-influenced path lets an absolute path such as /etc/passwd or the Windows hosts file be read without any traversal sequence at all.**

In practice on HTB this shows up as: | `/index.php?language=....//....//....//....//etc/passwd` | Bypass basic path traversal filter |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | Bypass filters with URL encoding |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with null byte (obsolete) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | Read PHP with base64 filter |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/28. File Inclusion/File Inclusion.md (973 words, classified web).

*Disproof:* Refuted when the application validates the path against an allow-list of permitted directories rather than rejecting traversal sequences, in which case an absolute path outside the allow-list is refused.

**php://filter with a base64-encode conversion stream reads a PHP source file as base64, turning a file read into source disclosure that reveals credentials inside the code.**

In practice on HTB this shows up as: | `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with null byte (obsolete) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | Read PHP with base64 filter |
## Remote Code Execution

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/28. File Inclusion/File Inclusion.md (973 words, classified web).

*Disproof:* Refuted when the wrapper scheme is disabled or the allow-list excludes any path containing a stream wrapper, in which case the request returns no source text.

## Variations

**A local file inclusion filter that strips '../' is bypassed by re-encoding the traversal (%2e%2e%2f), because the filter matches the decoded form the request never carries.**

In practice on HTB this shows up as: | **LFI Bypasses** |
| `/index.php?language=....//....//....//....//etc/passwd` | Bypass basic path traversal filter |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | Bypass filters with URL encoding |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with null byte (obsolete) |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/28. File Inclusion/File Inclusion.md (973 words, classified web).

*Disproof:* Refuted when the server percent-decodes the parameter before filtering, in which case the encoded sequence is normalised to ../ and rejected; the bypass only exists where filtering happens on the raw, undecoded request value.

**Confining the resolved path under a base directory by string prefix does not contain a symbolic link, because resolving the link replaces the component and discards all preceding parts of the path when the link body is absolute.**

The kernel's own description of symlink resolution is the mechanism, and it is why every prefix check on a resolved path is best-effort. Conceptually symbolic links could be handled by editing the path; if a component name refers to a symbolic link, then that component is replaced by the body of the link and, if that body starts with a '/', then all preceding parts of the path are discarded. So an attacker who can write one entry inside an otherwise-confined directory - through an upload feature, an archive extraction that preserves links, a build artefact, a cache directory, or a shared volume - plants a link to /etc/passwd and every later request that reads through it lands outside the base directory while every string in the request looks clean. The hunting technique follows directly: confirm the confined directory is writable by the attacker, then look for link creation in the upload or extract path, and prove the read by fetching content only the link target could serve. Note the same applies to archive extraction, which is the most common way these links appear in practice.

*Disproof:* The claim is false when the open itself is confined below the base rather than merely checked - resolving with an openat-style call relative to a directory file descriptor for the base directory, so the kernel performs component resolution with that directory as the root and cannot escape it by any path, because a '..' or an absolute link body cannot climb above the descriptor. It is also false where the service runs with a chroot, a container mount namespace, or a filesystem sandbox that makes the out-of-tree target unreadable, in which case the symlink exists but reaches nothing. And the finding needs the write: an attacker-controlled directory that is not writable gives no place to plant the link, so a report without a demonstrated link creation is a hypothesis.

**A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.**

Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory. The bypass is proven when the encoded form returns a file body the literal form is rejected from, because characters other than the reserved set are equivalent to their percent-encoded octets, so the two forms can differ as strings while naming the same normalized path. Note that a filter which decodes once and a backend which normalizes twice is the common shape of this bypass, and comparing as a simple string versus syntax-based normalization is exactly where the two disagree.

*Disproof:* If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.path_traversal.auto.01` — path_traversal: observe, exercise, confirm (goal: `Establish, exercise and confirm a path_traversal condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A response whose echoed path has ./ and ../ components stripped is consistent with normalisation by the client, the server, the framework, or the terminal - it does not by itself evidence an input filter, and it is not proof the traversal failed either.**

The corpus already holds the differential rule that a normalised payload returning identical content is uninformative; this is the complementary trap. When you submit ../../etc/passwd and the error message shows ../ cleaned to / or the path rendered canonicalised, the tempting reading is 'a filter caught it', and the report gets written as a mitigation. The alternative readings are at least as likely: the URL library parsed and re-serialised the path, the framework logged the normalised form, the terminal or the shell echoed a resolved path, or the browser sent a canonicalised request before it ever reached the server. The kernel documentation reminds you that path handling has more than one stage - components are separated from slashes, and each component is resolved with rules of its own - so a cleaned echo is evidence about one stage at most. The reportable observation is the file content, and the absence of a filter is only established by a payload that traverses successfully through a different encoding or separator.

*Disproof:* The claim is false when the normalisation is provably server-side and effective - you can show the request as received by the origin, for example through a request log or a reflected value that only the server could have computed, and the traversal payload in that same form still fails, which is a genuine control. It is also false where the client is not in the picture at all: a request made from a script with a raw socket, a binary body carrying the path, or a file upload field bypasses any browser canonicalisation, so evidence from that channel is not subject to this ambiguity. And a genuinely successful read is a finding regardless of how many stages normalised the string on the way in, because the read happened.

**A file-serving helper whose first argument is documented as a trusted path is not a traversal candidate, because nothing in that signature claims the caller controls it - the bug is at the call site, not in the helper.**

Werkzeug states the trust assumption at the point where testers most often misread the API. On send_file the documentation says never to pass file paths provided by a user, that the path is assumed to be trusted so a user could craft a path to access a file you didn't intend, and directs you to send_from_directory to safely serve user-provided paths. That is a two-function distinction with a security boundary in it: one takes a trusted path, one takes a client path and confines it using safe_join so the path coming from the client is not maliciously crafted to point outside the specified directory. A report that says 'send_file is vulnerable to traversal' is reporting the framework's documented contract. The finding only exists when a call site passes request data into the trusted-path function, and that call site is where the evidence has to come from.

*Disproof:* The claim is false when the helper is nonetheless reached with attacker-controlled data - a handler that does new = send_file(request.args['name']) has the vulnerability regardless of what the documentation says, and the report is correct even though the blame is shared. It is also false when the path is trusted but the file it points to is not, which is a distinct and very productive finding: an attacker who can create a symlink or an archive entry inside a trusted directory escapes the directory without any traversal string at all, so no amount of argument validation would have helped. And the rule does not apply to the confined function: send_from_directory's safe_join behaviour and its 404 for a path that does not point to an existing regular file are the control, and an endpoint using it is not a traversal candidate on the argument alone.

**A filename you supplied appearing in a traversal error page or a session cookie is not a file read; the finding needs file CONTENT returned as the response body.**

Discard the report when the only artefact is your own filename echoed back in an error message, a stack trace, a directory listing of the web root, or a session cookie dropped on a custom 404 page, because none of those read a file outside the intended root. The finding survives when the response body contains data from the targeted file and that content differs from anything served by the same route with a legitimate name.

*Disproof:* If the same route serves a fixed placeholder body for every nonexistent path including your traversal form, the identical-response rule applies and the report is a false positive; if any one form returns real file bytes, the finding is real regardless of what the other forms did.

**A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.**

Discard the finding when your encoded or dot-segment payload returns byte-identical content to the same request with a harmless filename, because the response is the normalized path, a redirect, or a fixed error page rather than a different file. The finding survives when the traversal returns content you can only have reached by leaving the intended directory, such as a system file or a config with credentials, and when the same payload works on more than one traversal encoding.

*Disproof:* If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it.

## Validation

**Behaviour on a static-file prefix says nothing about a parameterised download handler, and the reverse holds too - each endpoint needs its own probe because the two are served by different code entirely.**

Django's description of its development static helper makes the split explicit and it generalises to every stack: the helper works only in debug mode and only if the given prefix is local, and it only serves the actual STATIC_ROOT folder, it doesn't perform static files discovery, and static files are served via a wrapper at the WSGI application layer so static files requests do not pass through the normal middleware chain. Three consequences for a hunter. A static prefix that returns 403 or 404 for ../ proves nothing about the media or download handler, because different code serves it. Middleware-based authorisation and logging do not run on the static route at all, so the absence of an auth check there is not a finding either. And the user-upload media handler is a separate surface entirely - during development you can serve user-uploaded files from MEDIA_ROOT, and that endpoint takes an attacker-supplied filename by design. Test each file-serving surface on its own terms.

*Disproof:* The claim is false when both surfaces are served by the same confined component - a single static-file handler in front of every asset class, or a CDN or object-store gateway that applies one prefix rule to all buckets - in which case the static route's behaviour is genuinely informative about the download route. It also fails when the static surface is served by the web server itself from a document root, since the server's own path handling is a separate implementation and equally consistent across every alias it serves. And a specific finding on either endpoint still stands on its own evidence; this rule is only about the transfer of conclusions between endpoints.

**Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.**

A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not. Replace the calibration probe with a path that exists only on the filesystem, and confirm it reads back only when the disk branch is live. Prefer a harmless marker file over a credential or key so the validation leaves no secret in the scan log, and re-run the identical request to show the effect is reproducible.

*Disproof:* If a file that exists only on disk returns 404 or an error while the bundled asset returns 200, the read comes from the classpath and the finding is not actionable on that host.

**To decide this case, observe: Discard the report when the only artefact is your own filename echoed back in an error message, a stack trace, a directory listing of the web root, or a session cookie dropped on a custom 404 page, because none of those read a file outside the intended root.**

Derived from path_traversal.fprule.error_page_echo_is_not_a_file_read, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.fprule.error_page_echo_is_not_a_file_read) states the full boundary.

**To decide this case, observe: Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory.**

Derived from path_traversal.bypass.percent_encoding_normalization_defeats_allowlist, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.bypass.percent_encoding_normalization_defeats_allowlist) states the full boundary.

**To decide this case, observe: A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not.**

Derived from path_traversal.validation.disk_only_file_probe, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.validation.disk_only_file_probe) states the full boundary.

## Impact

**An LFI sink is an execution primitive rather than a read primitive, so the moment it can be pointed at a file the tester controls the included content runs with the web server's privileges.**

An LFI sink is an execution primitive rather than a read primitive, so the moment it can be pointed at a file the tester controls the included content runs with the web server's privileges.

HackTricks reference: LFI2RCE via Eternal waiting (pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md)

*Disproof:* Refuted if the sink returns the uploaded file's content as inert data without executing, for example because the include is downgraded to a read or the file's extension is never interpreted.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557>
- **blog.qualys.com** (research)
  - <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/22.html>
- **docs.djangoproject.com** (research)
  - <https://docs.djangoproject.com/en/5.0/howto/static-files/>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **kernel.org** (writeup)
  - <https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html>
- **man7.org** (research)
  - <https://man7.org/linux/man-pages/man2/open.2.html>
- **owasp.org** (cheatsheet)
  - <https://owasp.org/www-community/attacks/Path_Traversal>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/file-path-traversal>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities>
  - <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/28.%20File%20Inclusion/File%20Inclusion.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files.md>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
- **werkzeug.palletsprojects.com** (writeup)
  - <https://werkzeug.palletsprojects.com/en/stable/utils/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
