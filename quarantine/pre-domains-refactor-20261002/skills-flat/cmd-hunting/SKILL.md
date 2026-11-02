---
name: cmd-hunting
description: Use when hunting OS Command Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# OS Command Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 78 · OWASP A03:2021
> evidence: 7 items, 7 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

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

- A separator character appended after an otherwise valid argument to a host or exec-style parameter causes the shell to run a second command, and its presence is provable by an outbound callback rather than by response reflection.
  - **Disproof:** Show that the outbound connection you observed is emitted by the application's own pre-existing behaviour on that endpoint (for example it always contacts a monitoring or asset-lookup service) rather than by the injected command, by repeating the benign baseline and observing the same callback.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
- An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.
  - **Disproof:** Show that the server ignores the tested header entirely for command execution - the same header value produces no child process and no outbound callback, and the application's own handling is a plain string compare. Then header-borne injection is not reachable on that target and the coverage gap does not apply.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## Validation bar (how to prove it)

- A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.
  - **Disproof:** The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.
  - Sources: <https://trustedsec.com/blog/most-reported-web-findings-of-2023> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

## False-positive rules (when to reject it)

- A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.
  - **Disproof:** Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>

---
Full class document: `skills/Web/cmd/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
