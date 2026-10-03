# Methodology — OS Command Injection

> Derived from 18 verified items. Regenerate with `python -m wks.methodgen --class cmd --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Attacker input reaches a shell or process launcher and becomes part of the executed command.

**References.** CWE-78 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.**

Baseline: POST to a diagnostic endpoint with host=<valid-hostname> and observe the app invoke a helper process. Variant: the same field carrying the valid hostname followed by a shell metacharacter. The falsifiable test is not whether the response changes but whether a shell metacharacter is interpreted AT ALL. Black Hills describes exactly this boundary: their target was Apache on Red Hat and the semicolon at the start of the value separated the injected command from the original one the application expected, which means the app was building a shell command line rather than an argv array. Mandiant's source-code-review pipeline reaches the same conclusion structurally - it traces user input forward and asks whether the value ever reaches a dangerous sink, a function where malicious input could execute and cause harm, and it names command injection as a class only surfaced by that trace. So the prerequisite is a source-level determination: the sink must be a shell-invoking call, not an execve-style spawn. A parameterised subprocess call with a fixed argv and no shell is NOT this class regardless of what bytes it contains.

- *Disproof:* Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review)

**A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.**

The naive triage error: grep the code, find an escaping or validation call upstream of the sink, close the ticket. The falsifiable test is to trace the value across every hop, because the sanitizing call may guard one branch while a second path (a different HTTP verb, a JSON field instead of a form field, a batch job, an admin route) reaches the same sink unfiltered. Mandiant's source-code-review harness makes this structural: analysing an entry point in isolation is rarely sufficient because critical components like sanitizers, permissions, and routing conditions are often highly distributed, and a dedicated enrichment agent is dispatched per entry point to follow that distribution before a conclusion is drawn. The real-world failure mode is recorded verbatim by Black Hills, whose tester was convinced he had command injection while nothing worked, because he was reasoning from a single request shape rather than the set of shapes the sink accepts. So the prerequisite is: demonstrate reachability of the sink from a request-controlled value and enumerate every distinct path that reaches it. Prove the class boundary is crossed by showing data flow into the sink, not by showing the absence of a sanitiser string nearby.

- *Disproof:* Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.**

Differential test: send the identical working injected request repeatedly, appending one harmless padding character at a time. Black Hills ran exactly this bisection and found a hard 32-character ceiling on the command length, which they attributed to the value being written to a database first. The signal matters because it separates two opposite conclusions. If a ceiling exists but metacharacters beyond it are silently truncated mid-token, the app has no metacharacter filter at all and the finding is command injection with a length constraint. If instead the app rejected the request specifically on detecting a metacharacter at any position, that would be a filter. The differential is whether the ceiling moves when you pad with a benign character and whether the truncation position is stable and predictable: a stable ceiling that truncates rather than rejects is a storage-width artefact. Measure each field separately, since ceilings are usually per-column. This signal also explains why negative results in this class are frequently misreported as not vulnerable rather than as not yet characterised.

- *Disproof:* Show that the ceiling position shifts with the position of the metacharacter, or that requests above the ceiling are rejected with a validation error rather than silently accepted-and-truncated. That would indicate input filtering, not storage-width truncation.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.**

Request shape: a diagnostic endpoint that shells out to a network utility, with the host field set to a valid hostname. The benign baseline produces normal output. The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control. The differential lands on YOUR listener, not in the HTTP response. Black Hills injected a ping and confirmed receipt with a packet capture on their external host, which is a cleaner proof than any response artefact. That asymmetry matters for evasion: a command whose output is never returned still executes, so absence of output is not evidence of absence of execution. Keep the observable side effect non-destructive (a single outbound connection) so the test is reversible and leaves no artefact on the target. Placement note: a leading separator suffices when the app's own command text precedes your value, while a trailing separator is required when your value precedes a trailing argument the app appends.

- *Disproof:* Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances)

**An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.**

Request shape: a normal-looking request carrying an ordinary vendor or protocol-specific header whose value is an encoded command, executed by a handler component on the server. Mandiant documented this exact pattern on exploited NetScaler gateways: one variant read Base64-encoded commands out of the HTTP_NSC_LDAP header and executed them via shell_exec() while returning Base64-encoded output, and a sibling variant did the same with the HTTP_NSC_CLIENTTYPE header. The parameter-borne variant of the same class is the semicolon-separated command Black Hills found appended after a valid hostname, so both halves of this item are attested: the class is not header-specific, but the header surface is the one automated coverage misses. Detection framing from the advisory is behavioural rather than signature-on-URI: watch for the execution sinks and for process spawns correlated with unusual header values on authenticated business endpoints. The hunting rule that follows is concrete - when a body-parameter pass comes back clean on an appliance or gateway, enumerate the request headers the application already reads and test each for the same sink.

- *Disproof:* Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.**

Validation protocol, in order. First establish the control: issue the benign request (valid hostname, no metacharacter) and confirm your listener receives nothing. Then issue the variant with the separator and a probe directed at your listener, and confirm exactly one connection arrives inside the request's latency window. Black Hills used precisely this control - a ping they captured with tcpdump on their own external server - and it is the step most often skipped, which is why testers concluded nothing worked while already holding confirmed injection. The falsification side is equally load-bearing: if the endpoint's normal behaviour already contacts that host (asset lookup, monitoring agent, webhook), the callback is noise and proves nothing. So the control is mandatory, and if you cannot run one, the honest report says unconfirmed rather than confirmed. Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop. Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.

- *Disproof:* The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [trustedsec.com](https://trustedsec.com/blog/most-reported-web-findings-of-2023)

**The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.**

Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.

- *Disproof:* If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/subprocess.html); [nodejs.org](https://nodejs.org/api/child_process.html)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.**

This rule prevents an UNDER-report, which is the more expensive error than a false positive. The tell is a hard byte ceiling at which the payload silently stops having effect, with no validation error and no shift in position relative to the metacharacter. Black Hills initially concluded they were stuck, then bisected with padding and found a 32-character ceiling they attributed to a database write - the injection had been real the whole time. A reviewer who sees that a 60-character payload did not work and records filtered has made exactly that mistake. The rule: truncation is not filtering. Falsification is cheap and must be done - pad the payload with a benign character to isolate the ceiling, then re-test with a SHORT payload that fits underneath it. If the short payload executes, there is no filter and the ceiling is merely a constraint to design around. Mandiant's post is the right posture to cite when escalating this, because human-in-the-loop validation of confirmed findings effectively minimizes false positives while the harder problem the harness still has to solve is false negatives: a quiet ceiling is exactly where those hide.

- *Disproof:* Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/os-command-injection-pain-gain); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review)

**Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather...

Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When an injection point accepts a command separator and the second com" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances); [trustedsec.com](https://trustedsec.com/blog/most-reported-web-findings-of-2023)

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

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file.**

Mechanism: The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.

- *Disproof:* It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/subprocess.html); [nodejs.org](https://nodejs.org/api/child_process.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
