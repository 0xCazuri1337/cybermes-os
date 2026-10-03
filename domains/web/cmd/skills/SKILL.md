---
name: cmd-hunting
description: Use when hunting OS Command Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# OS Command Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 78 · OWASP A03:2021
> evidence: 27 items, 21 supported, 5 FP rules, 1 chains
> maturity: **mature**

Attacker input reaches a shell or process launcher and becomes part of the executed command.

**Also called:** command injection, rce via command, os command injection


## Prerequisites (do not start without these)

- OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.
  - **Disproof:** Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.
  - **Disproof:** Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Recon signals (where to look)

- When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.
  - **Disproof:** Show that the ceiling position shifts with the position of the metacharacter, or that requests above the ceiling are rejected with a validation error rather than silently accepted-and-truncated. That would indicate input filtering, not storage-width truncation.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Techniques (what to change)

- Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled terminati".
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-".
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on".
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Because exploitation can require very little traffic, volume-based anomaly detection alone".
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the".
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.
  - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
  - Sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands. _(unverified)_
  - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
  - Sources: <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Tests

- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.a_404_on_the_injected_path_is_not_evidence_the_endpoint_is_safe) states the full boundary.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
- To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.escapeshellcmd_is_not_a_substitute_for_argument_escaping) states the full boundary.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.argv_passing_is_not_injection_even_when_the_argument_contains_shell_metacharacters) states the full boundary.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.bypass.shell_true_or_shell_option_reopens_injection_in_an_otherwise_safe_call) states the full boundary.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.prove_execution_with_a_unique_marker_in_the_output_not_a_timeout) states the full boundary.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>

## Validation bar (how to prove it)

- A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.
  - **Disproof:** The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.
  - **Disproof:** If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>

## False-positive rules (when to reject it)

- A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.
  - **Disproof:** Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.
  - **Disproof:** It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
- Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.
  - **Disproof:** It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
- Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When an injection point accepts a command separator and the second com" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
- Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.
  - **Disproof:** It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>

## Evidence requirements

- A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- A convincing observation for this class is: The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.tech.command-separator-appended-after-valid-argument) states the full boundary.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Defence bypasses

- The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file.
  - **Disproof:** It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.
  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>

---
Full class document: `domains/web/cmd/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
