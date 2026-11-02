# Internal Network Reconnaissance

## Definition

An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["internal recon", "internal reconnaissance", "internal enumeration", "host discovery", "network mapping", "subnet discovery", "service enumeration", "port scan"]

Canonical home for `internal_recon`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**

h no edits. ","attrs":{"style":{"font-size":"11pt"}}}]},{"uid":"926c1ce8624240f59b682fbc73990e0a","type":"esqlSnippet","attrs":{"code":"/*\n Broad sweep: hunt one user's activity across every linked project.\n*/\nFROM logs-* METADATA _index\n /* METADATA _index is your project attribution. Linked-project rows arrive\n with the project alias as an index prefix; there is no ECS \"project\"\n field. If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. Dragging full _source at depth was many times\n slower than projecting columns in our testing. If a cross-project query\n feels slow, check this before you blame the fan-out. */\n| SORT @timestamp DESC\n| LIMIT 500"},"children":[{"text":""}]},{"uid":"acbee15c9fcd40d29fc72518a4df15d2","type":"p","children":[{"text":""}],"attrs":{}},{"uid":"36f15cd16e8c4b6b9a44352c47a0c767","type":"image","attrs":{

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".

**Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.**

ed in August is a Java deserialization vulnerability in Log4j 2's `FilteredObjectInputStream`, and we reproduced it on official Maven Central `log4j-api` and `log4j-core 2.26.1`. Getting to command execution took two more things that Log4j itself does not ship. You need a process that still deserializes Java-serialized `LogEvent` objects, and you need a gadget library already sitting on that JVM. Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging. In this post, we will cover:\n\n* The mechanism, cited from the official `2.26.1` source, and how it differs from Log4Shell.\n* What we did and did not observe in the lab, including the two conditions for command execution.\n* Which Elastic rules would fire on post-exploitation.\n* Hunting queries for Java-spawned shells and leftover serialized `LogEvent` collectors.\n\n## Why Apache does not cla

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".

**We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).**

alize log-event streams; bypasses of that allowlist are treated as hardening, not as product vulnerabilities; the application that deserializes is responsible for validating the byte stream.\n\nThis post is grounded in public sources, Apache's own security page, discussion [logging-log4j2#4168](https://github.com/apache/logging-log4j2/discussions/4168), and a lab we ran on official `2.26.1` JARs. We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`). A separate process can *receive* those events. One historical way of receiving events was Java serialization: read an `ObjectInputStream` and cast to `LogEvent`.\n\nThat receive style is how [CVE-2017-5645](https://nvd.nist.gov/vuln/detail/CVE-2017-5645) worked. Apache's advisory: when the TCP or UDP socket server received serialized log events, a crafted binary payload could execute code. Affect

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".

**Chained together, they let an attacker-controlled object graph deserialize with no filter applied.**

https://github.com/apache/logging-log4j2/discussions/4168) on 1 July 2026 (`MarshalledObject.get()` deserializes with no Log4j filter). That discussion frames the work as 2.x hardening. Issue #4255 later named the same path.\n\n## How the Java deserialization allowlist bypass works\nNone of the pieces here is a bug on its own. The bypass comes from three behaviors in the official `2.26.1` source. Chained together, they let an attacker-controlled object graph deserialize with no filter applied. Here they are in order:\n\n| Step | Component | Behaviour | Why it matters |\n| :---- | :---- | :---- | :---- |\n| 1 | `SerializationUtil.REQUIRED_JAVA_CLASSES` | `java.rmi.MarshalledObject` sits on the allowlist as a Message delegate | The carrier class is permitted by design |\n| 2 | `FilteredObjectInputStream.resolveClass()` | Checks only class descriptors present on the stream it reads | A pa

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".

**The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.**

= null) {\n try {\n return marshalledMessage.get();\n } catch (final Exception ex) {\n // ignore me\n }\n }\n return new SimpleMessage(messageString);\n}\n```\n\nSource: [`Log4jLogEvent.java` at `rel/2.26.1`](https://github.com/apache/logging-log4j2/blob/rel/2.26.1/log4j-core/src/main/java/org/apache/logging/log4j/core/impl/Log4jLogEvent.java#L1265-L1274). Any exception from `get()` is processed. The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`. On JDK 9+, `MarshalledObject` can copy the *enclosing* stream's JEP 290 `ObjectInputFilter`. `FilteredObjectInputStream` in 2.26.1 does not call `setObjectInputFilter()`, so that copy is `null` unless something else installed a filter. Discussion #4168 states the same Java 8 / Java 9+ split.\n\nLog4j already has a nested-object path that *re-applies* the filter: `SerializationUtil.writeWrappedObj

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".

**The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.**

`TcpSocketServer` / `ObjectInputStreamLogEventBridge` are gone from current `2.x` `log4j-core` sources. For current versions, the remaining exposure is leftover or custom code that still does new `FilteredObjectInputStream(socket.getInputStream())` and `readObject()` into a `LogEvent`. Historical `TcpSocketServer` constructed new `ServerSocket(port)`, which listens on all interfaces of that host. The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it. Whether a given leftover collector is reachable without credentials depends on how it was deployed. We are not stating that every collector is unauthenticated.\n\n## What we reproduced on Log4j 2.26.1\nWe used official Maven Central `log4j-api` 2.26.1 and `log4j-core` 2.26.1. The receiver implemented the public FOIS-plus-`LogEvent` read, bound to loopback for the run.\n\n* A class that `FilteredO

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".

**Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.**

ctInputStream` in `log4j-api` |\n| :---- | :---- | :---- |\n| `2.6.2`, `2.7` | absent | absent |\n| `2.8` | present | absent |\n| `2.8.2` | present | present (log4j-core) |\n| `2.9.1,` `2.10.0` | present | absent |\n| `2.11.0` through `2.26.1` | present | present (log4j-api) |\n\nThe bypass requires both the `marshalledMessage` field and a `FilteredObjectInputStream` to be the bypassed component. Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. We did not test every 2.x release, nor did we test Log4j 3 (discussion [#4168](https://archive.ph/Xowgn) says serialization is dropped there).\n\nThe defensive takeaway is the classpath: if the JVM that deserializes `LogEvent`s also ships a known gadget library, command execution is in play. If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Settin

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".

**If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.**

ions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. We did not test every 2.x release, nor did we test Log4j 3 (discussion [#4168](https://archive.ph/Xowgn) says serialization is dropped there).\n\nThe defensive takeaway is the classpath: if the JVM that deserializes `LogEvent`s also ships a known gadget library, command execution is in play. If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1. Deploy [Elastic Defend](https://www.elastic.co/docs/solutions/security/configure-elastic-defend) with process and network events on hosts that run JVMs (Complete EDR if you can).\n2. Enable the pre-built SIEM rules listed under Detection. \n3. Inventory processes that deserialize Java-serialized `LogEvent`s: leftover `TcpSocketServer`, `log4j-server` samples, `SerializedLayout` on a socket, or an

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".

**Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**

RFC 1918 states the consequence directly: addresses in private space are unique only within the enterprise, or among cooperating enterprises, so a private address identifies a host only relative to a vantage point inside the same space. That is the reason internal recon is inference: a DHCP-assigned address in a segment that conventionally serves a particular role is evidence about what runs there, and the reverse mapping — the address you can reach, the name you can resolve — is what turns reachability into a map. Two operational rules follow. First, private addresses must not be propagated across inter-enterprise links, so a private address appearing in external DNS records or leaked logs is itself an information disclosure. Second, because renumbering is costly, address-to-role mappings are stable, which is exactly what makes them predictive and worth enumerating deliberately rather than by opportunistic scanning.

*Disproof:* If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.

## Variations

**Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.**

A clean process-creation log is therefore not exculpatory, and a hunter who greps command-line telemetry for enumeration arguments will find nothing. Detection has to move to network-side RPC traffic and to the proxy process itself rather than to the command line the operator never typed. The claim is falsified if Sysmon or EDR process telemetry still captures the full argument string for the proxied invocation, which would mean the proxy does not actually strip it from process creation events.

*Disproof:* If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ad-enum-to-kerberoast-to-lateral-execution` — Directory enumeration to SPN enumeration to kerberoasted service account to lateral execution (goal: `domain_wide_lateral_movement`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a internal_recon finding until it is distinguished from the adjacent behaviour this class also covers. "A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never..." and "Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never...

Adjacent behaviour that produces the same observable result: Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Routing rpcclient enumeration through a Cobalt Strike socks proxy caus" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
**Hypothesis:** A single native enumeration command observed on a host is evidence of attacker reconnaissance of the internal network.
- Invalidated by: The identical command is part of the documented administrative routine and appears on managed hosts under their own credentials; no enumerated name is referenced by any subsequent authentication event, so nothing downstream consumed the output.
- **Rejection rule:** One enumeration command is dual use. Before reporting reconnaissance, show the same command in the admin baseline and show a downstream consumer - an authentication event, a connection, or a file access - that references an enumerated name. Absent the consumer you have an unproven telemetry signal.

## Validation

**To decide this case, observe: erate domain controllers and trust status; the adversary reuses the binary rather than shipping a tool. The signal that distinguishes reconnaissance from administration is not the command but the temporal cluster: several of these commands inside a short window from a single process tree, a shape no administration workflow produces because an administrator queries one thing at**

Derived from internal_recon.fp_rule.admin_enumeration_command_is_dual_use, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (internal_recon.fp_rule.admin_enumeration_command_is_dual_use) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **elastic.co** (writeup)
  - <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md>
  - <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1918.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
