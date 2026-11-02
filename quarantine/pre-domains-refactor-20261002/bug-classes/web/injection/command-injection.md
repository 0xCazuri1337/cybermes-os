# OS Command Injection

## Definition

Attacker input reaches a shell or process launcher and becomes part of the executed command.

- **CWE:** 78
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["command injection", "rce via command", "os command injection"]

Canonical home for `cmd`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.**

Baseline: POST to a diagnostic endpoint with host=<valid-hostname> and observe the app invoke a helper process. Variant: the same field carrying the valid hostname followed by a shell metacharacter. The falsifiable test is not whether the response changes but whether a shell metacharacter is interpreted AT ALL. Black Hills describes exactly this boundary: their target was Apache on Red Hat and the semicolon at the start of the value separated the injected command from the original one the application expected, which means the app was building a shell command line rather than an argv array. Mandiant's source-code-review pipeline reaches the same conclusion structurally - it traces user input forward and asks whether the value ever reaches a dangerous sink, a function where malicious input could execute and cause harm, and it names command injection as a class only surfaced by that trace. So the prerequisite is a source-level determination: the sink must be a shell-invoking call, not an execve-style spawn. A parameterised subprocess call with a fixed argv and no shell is NOT this class regardless of what bytes it contains.

*Disproof:* Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.

**A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.**

The naive triage error: grep the code, find an escaping or validation call upstream of the sink, close the ticket. The falsifiable test is to trace the value across every hop, because the sanitizing call may guard one branch while a second path (a different HTTP verb, a JSON field instead of a form field, a batch job, an admin route) reaches the same sink unfiltered. Mandiant's source-code-review harness makes this structural: analysing an entry point in isolation is rarely sufficient because critical components like sanitizers, permissions, and routing conditions are often highly distributed, and a dedicated enrichment agent is dispatched per entry point to follow that distribution before a conclusion is drawn. The real-world failure mode is recorded verbatim by Black Hills, whose tester was convinced he had command injection while nothing worked, because he was reasoning from a single request shape rather than the set of shapes the sink accepts. So the prerequisite is: demonstrate reachability of the sink from a request-controlled value and enumerate every distinct path that reaches it. Prove the class boundary is crossed by showing data flow into the sink, not by showing the absence of a sanitiser string nearby.

*Disproof:* Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.**

Differential test: send the identical working injected request repeatedly, appending one harmless padding character at a time. Black Hills ran exactly this bisection and found a hard 32-character ceiling on the command length, which they attributed to the value being written to a database first. The signal matters because it separates two opposite conclusions. If a ceiling exists but metacharacters beyond it are silently truncated mid-token, the app has no metacharacter filter at all and the finding is command injection with a length constraint. If instead the app rejected the request specifically on detecting a metacharacter at any position, that would be a filter. The differential is whether the ceiling moves when you pad with a benign character and whether the truncation position is stable and predictable: a stable ceiling that truncates rather than rejects is a storage-width artefact. Measure each field separately, since ceilings are usually per-column. This signal also explains why negative results in this class are frequently misreported as not vulnerable rather than as not yet characterised.

*Disproof:* Show that the ceiling position shifts with the position of the metacharacter, or that requests above the ceiling are rejected with a validation error rather than silently accepted-and-truncated. That would indicate input filtering, not storage-width truncation.

## Exploitation

**A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.**

Request shape: a diagnostic endpoint that shells out to a network utility, with the host field set to a valid hostname. The benign baseline produces normal output. The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control. The differential lands on YOUR listener, not in the HTTP response. Black Hills injected a ping and confirmed receipt with a packet capture on their external host, which is a cleaner proof than any response artefact. That asymmetry matters for evasion: a command whose output is never returned still executes, so absence of output is not evidence of absence of execution. Keep the observable side effect non-destructive (a single outbound connection) so the test is reversible and leaves no artefact on the target. Placement note: a leading separator suffices when the app's own command text precedes your value, while a trailing separator is required when your value precedes a trailing argument the app appends.

*Disproof:* Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.

**An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.**

Request shape: a normal-looking request carrying an ordinary vendor or protocol-specific header whose value is an encoded command, executed by a handler component on the server. Mandiant documented this exact pattern on exploited NetScaler gateways: one variant read Base64-encoded commands out of the HTTP_NSC_LDAP header and executed them via shell_exec() while returning Base64-encoded output, and a sibling variant did the same with the HTTP_NSC_CLIENTTYPE header. The parameter-borne variant of the same class is the semicolon-separated command Black Hills found appended after a valid hostname, so both halves of this item are attested: the class is not header-specific, but the header surface is the one automated coverage misses. Detection framing from the advisory is behavioural rather than signature-on-URI: watch for the execution sinks and for process spawns correlated with unusual header values on authenticated business endpoints. The hunting rule that follows is concrete - when a body-parameter pass comes back clean on an appliance or gateway, enumerate the request headers the application already reads and test each for the same sink.

*Disproof:* Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.**

This rule prevents an UNDER-report, which is the more expensive error than a false positive. The tell is a hard byte ceiling at which the payload silently stops having effect, with no validation error and no shift in position relative to the metacharacter. Black Hills initially concluded they were stuck, then bisected with padding and found a 32-character ceiling they attributed to a database write - the injection had been real the whole time. A reviewer who sees that a 60-character payload did not work and records filtered has made exactly that mistake. The rule: truncation is not filtering. Falsification is cheap and must be done - pad the payload with a benign character to isolate the ceiling, then re-test with a SHORT payload that fits underneath it. If the short payload executes, there is no filter and the ceiling is merely a constraint to design around. Mandiant's post is the right posture to cite when escalating this, because human-in-the-loop validation of confirmed findings effectively minimizes false positives while the harder problem the harness still has to solve is false negatives: a quiet ceiling is exactly where those hide.

*Disproof:* Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.

## Validation

**A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.**

Validation protocol, in order. First establish the control: issue the benign request (valid hostname, no metacharacter) and confirm your listener receives nothing. Then issue the variant with the separator and a probe directed at your listener, and confirm exactly one connection arrives inside the request's latency window. Black Hills used precisely this control - a ping they captured with tcpdump on their own external server - and it is the step most often skipped, which is why testers concluded nothing worked while already holding confirmed injection. The falsification side is equally load-bearing: if the endpoint's normal behaviour already contacts that host (asset lookup, monitoring agent, webhook), the callback is noise and proves nothing. So the control is mandatory, and if you cannot run one, the honest report says unconfirmed rather than confirmed. Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop. Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.

*Disproof:* The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blackhillsinfosec.com** (blog)
  - <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- **cloud.google.com** (advisory)
  - <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances>
  - <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review>
  - <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era>
- **trustedsec.com** (blog)
  - <https://trustedsec.com/blog/most-reported-web-findings-of-2023>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
