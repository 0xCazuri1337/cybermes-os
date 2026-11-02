# Methodology — OS Command Injection

> Derived from 13 verified items. Regenerate with `python -m wks.methodgen --class cmd --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Attacker input reaches a shell or process launcher and becomes part of the executed command.

**References.** CWE-78 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.**

Baseline: POST to a diagnostic endpoint with host=<valid-hostname> and observe the app invoke a helper process. Variant: the same field carrying the valid hostname followed by a shell metacharacter. The falsifiable test is not whether the response changes but whether a shell metacharacter is interpreted AT ALL. Black Hills describes exactly this boundary: their target was Apache on Red Hat and the semicolon at the start of the value separated the injected command from the original one the application expected, which means the app was building a shell command line rather than an argv array. Mandiant's source-code-review pipeline reaches the same conclusion structurally - it traces user input forward and asks whether the value ever reaches a dangerous sink, a function where malicious input could execute and cause harm, and it names command injection as a class only surfaced by that trace. So the prerequisite is a source-level determination: the sink must be a shell-invoking call, not an execve-style spawn. A parameterised subprocess call with a fixed argv and no shell is NOT this class regardless of what bytes it contains.

- *Disproof:* Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.**

Request shape: a normal-looking request carrying an ordinary vendor or protocol-specific header whose value is an encoded command, executed by a handler component on the server. Mandiant documented this exact pattern on exploited NetScaler gateways: one variant read Base64-encoded commands out of the HTTP_NSC_LDAP header and executed them via shell_exec() while returning Base64-encoded output, and a sibling variant did the same with the HTTP_NSC_CLIENTTYPE header. The parameter-borne variant of the same class is the semicolon-separated command Black Hills found appended after a valid hostname, so both halves of this item are attested: the class is not header-specific, but the header surface is the one automated coverage misses. Detection framing from the advisory is behavioural rather than signature-on-URI: watch for the execution sinks and for process spawns correlated with unusual header values on authenticated business endpoints. The hunting rule that follows is concrete - when a body-parameter pass comes back clean on an appliance or gateway, enumerate the request headers the application already reads and test each for the same sink.

- *Disproof:* Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [owasp.org](https://owasp.org/www-community/attacks/Command_Injection)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.**

Mechanism: A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.

- *Disproof:* It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/subprocess.html); [php.net](https://www.php.net/manual/en/function.escapeshellarg.php)

**Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.**

Mechanism: Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.

- *Disproof:* It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/subprocess.html); [nodejs.org](https://nodejs.org/api/child_process.html)

**Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.**

Mechanism: Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.

- *Disproof:* It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/subprocess.html); [php.net](https://www.php.net/manual/en/function.escapeshellarg.php)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file.**

Mechanism: The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.

- *Disproof:* It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/subprocess.html); [nodejs.org](https://nodejs.org/api/child_process.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Impact

_What is actually demonstrable, and what to stop claiming._

**OS command injection is a high/critical-impact flaw: it yields remote code execution with the application's privileges, full server compromise, and the ability to pivot, escalate, exfiltrate data, and maintain persistence.**

Executed with the privileges of the vulnerable process, injected commands can read configuration files containing credentials, establish reverse shells, download post-exploitation tools, move laterally across the internal network, encrypt data, or deploy persistent implants. If the process runs as root or another highly privileged account, the compromise is total. The server becomes a platform for further attacks: pivoting to internal systems and creating footholds that survive the original fix. Real-world impact is documented in widely exploited vulnerabilities: CVE-2019-25224 (WordPress Database Backup plugin via mysqldump, unauthenticated RCE), CVE-2024-3400 (PAN-OS GlobalProtect, unauthenticated RCE), CVE-2024-21887 (Ivanti Connect Secure, chained with authentication bypass), and CVE-2014-6271 (Shellshock, RCE via Bash environment handling).

- *Disproof:* Command injection is not limited to disclosure of a single file or a trivially low-privilege account: it is a complete server compromise primitive when the process has elevated rights, and even limited-privilege executions chain into pivot, persistence, and data theft. Its severity is why PortSwigger rates it typically High and why it is also listed among the CWE top-25 rank 9 OS command injection weaknesses.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/kb/issues/00100100_os-command-injection); [secra.es](https://secra.es/en/blog/os-command-injection); [yeswehack.com](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
