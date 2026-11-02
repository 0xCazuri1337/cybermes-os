# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -73,4 +73,4 @@
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 
 ---
-Full class document: `domains/web/cmd/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
+Full class document: `domains/web/cmd/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
```

## 2026-10-02 19:37 — 96 diff lines
- items: 24 (supported 18), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 13 items, 13 supported, 2 FP rules, 1 chains
+> evidence: 24 items, 18 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -35,19 +35,19 @@
 
 ## Techniques (what to change)
 
-- Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access.
+- Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled terminati".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped.
+- Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority.
+- A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity.
+- Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Because exploitation can require very little traffic, volume-based anomaly detection alone".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation.
+- Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.
@@ -57,20 +57,59 @@
   - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
+## Tests
+
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page wi
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.a_404_on_the_injected_path_is_not_evidence_the_endpoint_is_safe) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
+- To decide this case, observe: ayload drop. Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.escapeshellcmd_is_not_a_substitute_for_argument_escaping) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows bein
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.argv_passing_is_not_injection_even_when_the_argument_contains_shell_metacharacters) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.bypass.shell_true_or_shell_option_reopens_injection_in_an_otherwise_safe_call) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
+- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload. How to apply it in the field: treat this as the validation it is — a hunter must be able to state
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.prove_execution_with_a_unique_marker_in_the_output_not_a_timeout) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
+
 ## Validation bar (how to prove it)
 
 - A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.
   - **Disproof:** The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.
+  - **Disproof:** If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
 ## False-positive rules (when to reject it)
 
 - A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.
   - **Disproof:** Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.
+  - **Disproof:** It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
+- Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.
+  - **Disproof:** It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 - Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When an injection point accepts a command separator and the second com" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+- Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.
+  - **Disproof:** It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
+
+## Defence bypasses
+
+- The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file.
+  - **Disproof:** It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when a single reachable configuration change or a file-type dispatch routes the same user input through a shell, since then the argv boundary that made the call safe no longer exists.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
 ---
 Full class document: `domains/web/cmd/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
```

## 2026-10-03 01:46 — 93 diff lines
- items: 27 (supported 21), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 24 items, 18 supported, 5 FP rules, 1 chains
+> evidence: 27 items, 21 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -37,44 +37,44 @@
 
 - Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled terminati".
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-".
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on".
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Because exploitation can require very little traffic, volume-based anomaly detection alone".
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.
   - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.
+  - Sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands. _(unverified)_
   - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+  - Sources: <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Tests
 
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page wi
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.a_404_on_the_injected_path_is_not_evidence_the_endpoint_is_safe) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
-- To decide this case, observe: ayload drop. Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.
+- To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.escapeshellcmd_is_not_a_substitute_for_argument_escaping) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows bein
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.argv_passing_is_not_injection_even_when_the_argument_contains_shell_metacharacters) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass if every reachable path uses the non-shell form and the platform is one where batch-file launching does not implicitly engage a shell; it is a bypass when
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.bypass.shell_true_or_shell_option_reopens_injection_in_an_otherwise_safe_call) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
-- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload. How to apply it in the field: treat this as the validation it is — a hunter must be able to state
+- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.prove_execution_with_a_unique_marker_in_the_output_not_a_timeout) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
@@ -100,10 +100,22 @@
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 - Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When an injection point accepts a command separator and the second com" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.
   - **Disproof:** It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
+
+## Evidence requirements
+
+- A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- A convincing observation for this class is: The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.tech.command-separator-appended-after-valid-argument) states the full boundary.
+  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Defence bypasses
 
```

## 2026-10-04 00:43 — 170 diff lines
- items: 27 (supported 21), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -20,108 +20,117 @@
 
 ## Prerequisites (do not start without these)
 
-- OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.
+- A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.
+  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.  _(merged 1 duplicate row(s))_
   - **Disproof:** Show a working end-to-end exploit where the value is passed as a discrete element of an argument vector to a process-spawn API that never invokes a shell interpreter (execve/posix_spawn, or StartProcess with an explicit argv and no cmd.exe). If the metacharacters still execute, the prerequisite as stated is false.
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.
-  - **Disproof:** Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Recon signals (where to look)
 
-- When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.
+- When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_
   - **Disproof:** Show that the ceiling position shifts with the position of the metacharacter, or that requests above the ceiling are rejected with a validation error rather than silently accepted-and-truncated. That would indicate input filtering, not storage-width truncation.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Techniques (what to change)
 
-- Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access. _(unverified)_
+- A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on".
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+- A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
+  - Sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
+  - Sources: <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+- Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Because exploitation can require very little traffic, volume-based anomaly detection alone".
+  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+- Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled terminati".
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped. _(unverified)_
+- Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-".
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on".
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Because exploitation can require very little traffic, volume-based anomaly detection alone".
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation. _(unverified)_
+- Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.
-  - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
-  - Sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands. _(unverified)_
-  - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
-  - Sources: <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.a_404_on_the_injected_path_is_not_evidence_the_endpoint_is_safe) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
-- To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.bypass.shell_true_or_shell_option_reopens_injection_in_an_otherwise_safe_call) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.argv_passing_is_not_injection_even_when_the_argument_contains_shell_metacharacters) states the full boundary.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php> · <https://nodejs.org/api/child_process.html>
+- To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.escapeshellcmd_is_not_a_substitute_for_argument_escaping) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.argv_passing_is_not_injection_even_when_the_argument_contains_shell_metacharacters) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.bypass.shell_true_or_shell_option_reopens_injection_in_an_otherwise_safe_call) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
-- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.
+- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.prove_execution_with_a_unique_marker_in_the_output_not_a_timeout) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
 ## Validation bar (how to prove it)
 
-- A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.
+- A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.  _(merged 1 duplicate row(s))_
   - **Disproof:** The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.
+- The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
 ## False-positive rules (when to reject it)
 
-- A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.
+- A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
+  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
+- A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.  _(merged 1 duplicate row(s))_
   - **Disproof:** Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.
-  - **Disproof:** It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
+- Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS adequate when every attacker-controlled value is passed as a quoted single argument to a function that treats the quote as a boundary; it is NOT adequate when the value is concatenated into a command string and escaped with the command-level routine, because escaping designed for one position does not establish quoting at an argument boundary and can leave separators live.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
-- Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.
+- Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 27 (supported 21), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -120,10 +120,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Establish the injectable parameter with a benign timing marker, then separate argument injection from command execution.
+2. Check the filter ladder in a fixed order -- quoting, escaping, allowlists -- and confirm the shell actually ran something (interactsh callback).
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 27 (supported 21), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -132,6 +132,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/cmd/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-28 14:45 — 24 diff lines
- items: 23 (supported 17), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 27 items, 21 supported, 5 FP rules, 1 chains
+> evidence: 23 items, 17 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -59,12 +59,6 @@
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.bypass.shell_true_or_shell_option_reopens_injection_in_an_otherwise_safe_call) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.fp_rule.argv_passing_is_not_injection_even_when_the_argument_contains_shell_metacharacters) states the full boundary.
-  - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php> · <https://nodejs.org/api/child_process.html>
 - To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
```

## 2026-10-28 17:55 — 38 diff lines
- items: 19 (supported 18), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 23 items, 17 supported, 5 FP rules, 1 chains
+> evidence: 19 items, 18 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -35,24 +35,12 @@
 
 ## Techniques (what to change)
 
-- A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on the same appliance is a strong exploitation signal and should be investigated with high priority.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A matching DTLS handshake failure followed within minutes by an NSPPE termination/crash on".
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 - A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.  _(merged 1 duplicate row(s))_
   - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
   - Sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.  _(merged 1 duplicate row(s))_ _(unverified)_
+- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.  _(merged 1 duplicate row(s))_
   - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
-  - Sources: <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- Because exploitation can require very little traffic, volume-based anomaly detection alone may not identify the activity.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Because exploitation can require very little traffic, volume-based anomaly detection alone".
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled termination of the NetScaler Packet Processing Engine (NSPPE) to establish initial root-level access.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of CVE-2026-88772 bypasses authentication and triggers an unhandled terminati".
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
-- Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-processing engine (nsppe) before it is dropped.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Relying exclusively on local NetScaler ACLs allows traffic to reach the vulnerable packet-".
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
+  - Sources: <https://owasp.org/www-community/attacks/Command_Injection> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the same time window as supporting evidence of potential exploitation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat unexpected HA failovers or appliance restarts on internet-facing Gateways within the".
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
```

## 2026-10-28 21:26 — 30 diff lines
- items: 25 (supported 24), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 19 items, 18 supported, 5 FP rules, 1 chains
+> evidence: 25 items, 24 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -93,6 +93,18 @@
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.tech.command-separator-appended-after-valid-argument) states the full boundary.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
+## Impact framing
+
+- OS command injection is a high/critical-impact flaw: it yields remote code execution with the application's privileges, full server compromise, and the ability to pivot, escalate, exfiltrate data, and maintain persistence.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Command injection is not limited to disclosure of a single file or a trivially low-privilege account: it is a complete server compromise primitive when the process has elevated rights, and even limited-privilege executions chain into pivot, persistence, and data theft. Its severity is why PortSwigger rates it typically High and why it is also listed among the CWE top-25 rank 9 OS command injection weaknesses.
+  - Sources: <https://portswigger.net/kb/issues/00100100_os-command-injection> · <https://secra.es/en/blog/os-command-injection> · <https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection>
+
+## Variants
+
+- Blind command injection occurs when the application does not return injected command output in the HTTP response; it is confirmed and exploited with time delays, output redirection to a readable file, and out-of-band (OAST) channels.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The absence of command output in the response does not mean the injection is unexploitable: the command can be executed and its effect observed through side channels (delayed response, a file later fetched, or an outbound DNS/HTTP pingback), so blind findings are still high-value.
+  - Sources: <https://portswigger.net/web-security/os-command-injection> · <https://secra.es/en/blog/os-command-injection> · <https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-os-command-injection>
+
 ## Defence bypasses
 
 - The concrete control that defeats command injection is the absence of a shell at the exec boundary, and the bypass is any code path that turns a safe argv-style call into a shell-invoking one, whether by enabling the shell option, using a legacy shell-invoking helper, or launching a Windows batch file.  _(merged 1 duplicate row(s))_
```

## 2026-10-28 21:46 — 11 diff lines
- items: 26 (supported 25), FP rules 5, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 25 items, 24 supported, 5 FP rules, 1 chains
+> evidence: 26 items, 25 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
```

## 2026-10-31 06:41 — 93 diff lines
- items: 26 (supported 13), FP rules 3, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 26 items, 25 supported, 5 FP rules, 1 chains
+> evidence: 26 items, 13 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -20,7 +20,7 @@
 
 ## Prerequisites (do not start without these)
 
-- A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.  _(merged 1 duplicate row(s))_
+- A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with the sink.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - OS command injection is only reachable when the attacker-controlled string is concatenated into a value handed to a shell interpreter, not merely passed as a discrete element of an argument vector to a process-spawn API.  _(merged 1 duplicate row(s))_
@@ -29,13 +29,13 @@
 
 ## Recon signals (where to look)
 
-- When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_
+- When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Show that the ceiling position shifts with the position of the metacharacter, or that requests above the ceiling are rejected with a validation error rather than silently accepted-and-truncated. That would indicate input filtering, not storage-width truncation.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Techniques (what to change)
 
-- A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.  _(merged 1 duplicate row(s))_
+- A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
   - Sources: <https://nodejs.org/api/child_process.html> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.  _(merged 1 duplicate row(s))_
@@ -47,19 +47,19 @@
 
 ## Tests
 
-- To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Keep the probe to a single outbound connection and tear the listener down immediately - this is a reachability test, not a payload drop.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Mechanism: The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cmd.validation.prove_execution_with_a_unique_marker_in_the_output_not_a_timeout) states the full boundary.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
 ## Validation bar (how to prove it)
 
-- A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.  _(merged 1 duplicate row(s))_
+- A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.  _(merged 1 duplicate row(s))_
+- The convincing command-injection evidence is a request/response pair where an injected unique marker string comes back verbatim in the command output or in an out-of-band callback, which separates real execution from a blocked or merely reflected payload.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the marker never appears anywhere the attacker can observe, there is no proof of execution and the report must stay at attempted-injection; a delay or an error message that echoes the payload back does not demonstrate that a process ran, because the echo alone is explained by reflection into the response.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
 
@@ -68,7 +68,7 @@
 - A 4xx response to an injected payload is not a defence, because many shells still execute the injected portion and the process status is then swallowed by the application, so a non-2xx proves nothing about whether the injected command ran.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is a genuine defence only when the payload never reached a shell, shown by an out-of-band absence of any effect including no DNS or callback attempt; a clean error page with no side-channel observation is inconclusive rather than exculpatory, and should be recorded as an untested negative.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://www.php.net/manual/en/function.escapeshellarg.php>
-- A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.  _(merged 1 duplicate row(s))_
+- A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - Applying a whole-command metacharacter escaper and calling the argument safe is the classic false negative, because that function is meant for sanitising a command string rather than for quoting a single argument, and the two goals fail in opposite directions.  _(merged 1 duplicate row(s))_
@@ -77,19 +77,19 @@
 - Concatenating user input into an argument vector without invoking a shell is not command injection, because the process never parses the argument as shell syntax; the finding only becomes real at the point a shell interpreter is explicitly engaged.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS injection when a shell is invoked explicitly with a single composed string, or when the runtime spawns a shell regardless of the call shape (batch files on Windows being the documented case); it is NOT injection when the value stays a discrete argv element in a call that does not implicitly choose a shell, because metacharacters in an unparsed argument have no meaning.
   - Sources: <https://docs.python.org/3/library/subprocess.html> · <https://nodejs.org/api/child_process.html>
-- Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a cmd finding until it is distinguished from the adjacent behaviour this class also covers. "A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather..." and "When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When an injection point accepts a command separator and the second com" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
-- A convincing observation for this class is: The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.tech.command-separator-appended-after-valid-argument) states the full boundary.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
```

## 2026-10-31 08:22 — 30 diff lines
- items: 26 (supported 14), FP rules 3, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 26 items, 13 supported, 3 FP rules, 1 chains
+> evidence: 26 items, 14 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -83,15 +83,15 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_ _(unverified)_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.fp_rule.auto.derived) states the full boundary.
-  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.validation.outbound-callback-with-baseline-control-confirms-execution) states the full boundary.
   - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - A convincing observation for this class is: The variant is the same hostname followed by a shell command separator and a trivially observable side effect: an outbound request from the server to an address you control.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.tech.command-separator-appended-after-valid-argument) states the full boundary.
-  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
+  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ## Impact framing
 
```

## 2026-10-31 08:23 — 20 diff lines
- items: 26 (supported 13), FP rules 3, chains 1, state mature

```diff
--- cmd@current
+++ cmd@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 78 · OWASP A03:2021
-> evidence: 26 items, 14 supported, 3 FP rules, 1 chains
+> evidence: 26 items, 13 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
@@ -83,7 +83,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When an injection point accepts a command separator and the second command runs, but appending trailing padding makes it stop working at a fixed byte count, the cause is upstream storage truncation rather than a filter on metacharacters.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cmd.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 - A convincing observation for this class is: Note the alternative validation channel if egress is blocked: command output shaped as a valid header line appears in the response headers rather than the body, which Black Hills exploited when only /etc/passwd returned.  _(merged 1 duplicate row(s))_ _(unverified)_
```
