# OS Command Injection

> surface: `web` · CWE: 78 · OWASP: A03:2021
> maturity: **mature** — 26 items, 13 supported, 3 FP rules, 1 chains

Attacker input reaches a shell or process launcher and becomes part of the executed command.

**Aliases:** command injection, rce via command, os command injection

## Prerequisite

- **OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.**  
  `high_confidence` · score 0.954 · disproved by: Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.**  
  `under_review` · score 0.8715 · disproved by: Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Signal

- **When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.**  
  `under_review` · score 0.899 · disproved by: Show that the ceiling position shifts with the position of the metacharacter, or that requests above the ceiling are rejected with a validation error rather than silently accepted-and-truncated. That would indicate input filtering, not storage-width truncation.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Technique

- **An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.**  
  `high_confidence` · score 0.948 · disproved by: Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
  sources: <https://owasp.org/www-community/attacks/Command_Injection> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.**  
  `under_review` · score 0.929 · disproved by: Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
  sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>

## Test

- **To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.**  
  `under_review` · score 0.893 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
  sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.**  
  `under_review` · score 0.8655 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.prove_execution_with_a_unique_marker_in_the_output_not_a_timeout) states the full boundary.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>

## Validation

- **A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.**  
  `under_review` · score 0.929 · disproved by: The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
  sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.**  
  `under_review` · score 0.8655 · disproved by: If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>

## Fp Rule

- **A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.**  
  `under_review` · score 0.899 · disproved by: Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.**  
  `high_confidence` · score 0.8655 · disproved by: It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
- **Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When an injection point accepts a command separator and the second com" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- **Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.**  
  `high_confidence` · score 0.838 · disproved by: It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
- **Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.**  
  `high_confidence` · score 0.838 · disproved by: It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
  sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>

## Evidence

- **A convincing observation for this class is: The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control.**  
  `under_review` · score 0.8815 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.tech.command-separator-appended-after-valid-argument) states the full boundary.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.**  
  `under_review` · score 0.8655 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
  sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.**  
  `under_review` · score 0.854 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.fp_rule.auto.derived) states the full boundary.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

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
