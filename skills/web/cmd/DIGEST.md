<!-- GENERATED from db/wks.db — do not edit -->
# OS Command Injection

> surface: `web` · CWE: 78 · OWASP: A03:2021
> maturity: **mature** — 26 items, 13 supported, 3 FP rules, 1 chains

Attacker input reaches a shell or process launcher and becomes part of the executed command.

**Aliases:** command injection, rce via command, os command injection

## Prerequisite

- **OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.**  
  `high_confidence` · score 0.954 · disproved by: Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Technique

- **An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.**  
  `high_confidence` · score 0.948 · disproved by: Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
  sources: <https://owasp.org/www-community/attacks/Command_Injection> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Fp Rule

- **A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.**  
  `high_confidence` · score 0.8655 · disproved by: It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
- **Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.**  
  `high_confidence` · score 0.838 · disproved by: It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
- **Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.**  
  `high_confidence` · score 0.838 · disproved by: It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>

## Impact

- **OS command injection is a high/critical-impact flaw: it yields remote code execution with the application's privileges, full server compromise, and the ability to pivot, escalate, exfiltrate data, and maintain persistence.**  
  `high_confidence` · score 0.795 · disproved by: Command injection is not limited to disclosure of a single file or a trivially low-privilege account: it is a complete server compromise primitive when the process has elevated rights, and even limited-privilege executions chain into pivot, persistence, and data theft. Its severity is why PortSwigger rates it typically High and why it is also listed among the CWE top-25 rank 9 OS command injection weaknesses.
  sources: <https://portswigger.net/kb/issues/00100100_os-command-injection> · <https://secra.es/en/blog/os-command-injection> · <https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection>

## Variant

- **Blind command injection occurs when the application does not return injected command output in the HTTP response; it is confirmed and exploited with time delays, output redirection to a readable file, and out-of-band (OAST) channels.**  
  `high_confidence` · score 0.854 · disproved by: The absence of command output in the response does not mean the injection is unexploitable: the command can be executed and its effect observed through side channels (delayed response, a file later fetched, or an outbound DNS/HTTP pingback), so blind findings are still high-value.
  sources: <https://portswigger.net/web-security/os-command-injection> · <https://secra.es/en/blog/os-command-injection> · <https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection>

## Bypass

- **The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file.**  
  `high_confidence` · score 0.838 · disproved by: It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>

## Vulnerability

- **OS command injection lets an attacker inject arbitrary operating system commands into a shell command built from unvalidated user input, giving full control of the host web server.**  
  `high_confidence` · score 0.89 · disproved by: If user-supplied input is never passed to a shell, if commands are built from fixed allowlisted values, or if metacharacters are stripped with a validated allowlist of permitted characters, injection is neutralized. A successful request showing only the intended fixed command (and no appended shell output) disproves exploitation.
  sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://portswigger.net/kb/issues/00100100_os-command-injection> · <https://portswigger.net/web-security/os-command-injection>

## Vulnerability Definition

- **OS command injection (CWE-78) lets an attacker inject and execute arbitrary operating-system commands on the server by passing unsanitized user input into a shell command interpreter.**  
  `high_confidence` · score 0.89 · disproved by: Command injection is NOT code injection: code injection adds code that the application runtime executes, whereas command injection extends the application's ability to run OS commands. The vulnerability is also not mitigated by simple blacklist filtering of shell metacharacters: PortSwigger explicitly warns that escaping shell metacharacters is too error-prone and bypassable, and the CWE-78 subtypes show that even an attacker-controlled argument for a fixed program (e.g. nslookup) is exploitable if command separators are not removed.
  sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://community.owasp.org/attacks/Command_Injection> · <https://portswigger.net/web-security/os-command-injection>

## Injection Techniques

- **Attackers chain or substitute commands using shell metacharacters that differ between Windows and Unix, so the return channel (in-band output vs blind) determines which technique works.**  
  `high_confidence` · score 0.8265 · disproved by: Not every injected payload produces visible output: command separators differ between Windows and Unix, and inline substitution/backgrounding behave differently, so the same parameter may be exploitable with & but not with ;, or only via a blind/OAST channel. Blind input is still exploitable through time delays and out-of-band calls.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html> · <https://portswigger.net/web-security/os-command-injection> · <https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection>

## Bypass And Tips

- **Implementing input validation requires care: blacklist filtering of shell metacharacters is fragile, escaping is unreliable, and even supposedly-safe escaping functions (escapeshellcmd) can be bypassed with argument injection; the robust path combines whitelists, parameterized APIs, and least privilege.**  
  `high_confidence` · score 0.818 · disproved by: Validation/escaping defenses fail in practice: escapeshellcmd does not stop option injection, a single strict allowlist cannot cover every legitimate input shape (e.g. a mail subject containing ; and >), and client-side checks are trivially bypassed. Blind/escaped contexts require indirect confirmation rather than direct output.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html> · <https://portswigger.net/web-security/os-command-injection> · <https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection>

## Prevention

- **The primary defense is to avoid invoking OS commands from application code; where that is unavoidable, use parameterized/argument-list APIs, strict allowlist validation, and least privilege as defense in depth.**  
  `high_confidence` · score 0.8055 · disproved by: OS commands are not always avoidable: legacy servers, mail, image conversion (ImageMagick), and diagnostics (ping) still require an external process, so relying solely on a blacklist or on a single function is insufficient; the two-layer defense only works if both layers are implemented and the process is not over-privileged.
  sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html> · <https://portswigger.net/kb/issues/00100100_os-command-injection> · <https://secra.es/en/blog/os-command-injection>
