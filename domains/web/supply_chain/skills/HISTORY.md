# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 18 (supported 18), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 18 (supported 18), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -98,4 +98,4 @@
 - `exposed_rmm` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/supply_chain/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
+Full class document: `domains/web/supply_chain/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
```

## 2026-10-02 19:37 — 73 diff lines
- items: 18 (supported 5), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 18 items, 18 supported, 2 FP rules, 1 chains
+> evidence: 18 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -20,7 +20,7 @@
 
 ## Recon signals (where to look)
 
-- A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.
+- A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety. _(unverified)_
   - **Disproof:** If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.
   - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
 - Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.
@@ -29,40 +29,40 @@
 
 ## Techniques (what to change)
 
-- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.
+- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
   - Sources: <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
-- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.
+- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Chained together, they let an attacker-controlled object graph deserialize with no filter applied.
+- Chained together, they let an attacker-controlled object graph deserialize with no filter applied. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).
+- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.
+- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.
+- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
-- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.
+- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.
+- Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.
+- After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.
+- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.
+- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.
+- Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.
```

## 2026-10-03 01:46 — 58 diff lines
- items: 24 (supported 11), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 18 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 24 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -22,7 +22,7 @@
 
 - A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety. _(unverified)_
   - **Disproof:** If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.
-  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
+  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
 - Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.
   - **Disproof:** Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.
   - Sources: <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
@@ -69,6 +69,21 @@
   - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
   - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
 
+## Tests
+
+- A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.
+  - **Disproof:** The claim is false when the candidate is rejected by the service - a 401 or an expired-token error is a placeholder, a documentation sample, or an already-revoked key, and reporting it as a live leak is the standard false positive here. It is also false when the only place the string appears is in a test fixture, an example file, or a fixture directory inside a source tree that is excluded from the published package, which is why the extraction target must be the shipped artifact rather than the repository. And it is false as an active compromise if the credential is scoped to an organization you are already authorized to test with a lower-privilege token of your own; in that case the correct claim is about scope hygiene rather than a stolen credential, and the report must say which account the token belonged to.
+  - Sources: <https://cwe.mitre.org/data/definitions/798.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
+- An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.
+  - **Disproof:** The claim is false if no lifecycle script executed during your install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform - and a script you never observed running proves nothing about execution. It is also false if the only effect was a compilation step confined to the package's own build directory producing the artifact the package documents it produces, which is normal packaging behaviour rather than a second delivery stage. And it is false where the observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time; trace the connection to a host that appears nowhere in the declared dependencies before treating it as exfiltration.
+  - Sources: <https://cwe.mitre.org/data/definitions/506.html> · <https://docs.npmjs.com/cli/v11/using-npm/scripts>
+- A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.
+  - **Disproof:** The claim is false if the recomputed digest matches the lockfile and the registry, since then the installed bytes are the published bytes and no substitution occurred on that path. It is also false if the version you flagged is simply newer than the one pinned - a version difference is an update decision, not evidence of tampering, and the digest is what settles it. And it is false as a compromise claim when the mismatch is confined to files the build never executes - a README, a test fixture, or a metadata file excluded from the install path - because the running code is unchanged; re-hash only the files actually loaded before reporting, and state which ones you excluded.
+  - Sources: <https://cwe.mitre.org/data/definitions/494.html> · <https://go.dev/ref/mod>
+- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.
+  - **Disproof:** The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window - the exposure is real but the mutation was not observed, and the report must be worded as a mutable reference rather than as a demonstrated tag move. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag, since the executed code is fixed. And it is false as an active compromise if the resolved commit's content matches the reviewed version and its signature verifies against the maintainer's key, since a moved ref that re-points at identical bytes changes nothing; verify the commit before reporting a supply-chain event rather than assuming one from the ref syntax.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/829.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
+
 ## Validation bar (how to prove it)
 
 - A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.
@@ -80,6 +95,15 @@
 - A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.
   - **Disproof:** Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
   - Sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
+
+## Evidence requirements
+
+- A convincing observation for this class is: The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.fp_rule.cve_listed_for_dependency_is_not_compromise) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
+- A convincing observation for this class is: Both halves of that statement - the publish and the consumer-side injection - are observable.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.validation.installed_artifact_matches_registry_publish_event) states the full boundary.
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
 
 ## Chaining opportunities
 
```

## 2026-10-04 00:43 — 164 diff lines
- items: 24 (supported 11), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -20,94 +20,91 @@
 
 ## Recon signals (where to look)
 
-- A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety. _(unverified)_
+- A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.
   - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
-- Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.
+- Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.  _(merged 1 duplicate row(s))_
   - **Disproof:** Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.
   - Sources: <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 
 ## Techniques (what to change)
 
-- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
-  - Sources: <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
-- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1. _(unverified)_
+- A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
+  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
+- After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- Chained together, they let an attacker-controlled object graph deserialize with no filter applied.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Chained together, they let an attacker-controlled object graph deserialize with no filter applied. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
+- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`). _(unverified)_
+- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
+- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
-- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.
-  - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
-  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
 
 ## Tests
 
-- A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.
+- A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the candidate is rejected by the service - a 401 or an expired-token error is a placeholder, a documentation sample, or an already-revoked key, and reporting it as a live leak is the standard false positive here. It is also false when the only place the string appears is in a test fixture, an example file, or a fixture directory inside a source tree that is excluded from the published package, which is why the extraction target must be the shipped artifact rather than the repository. And it is false as an active compromise if the credential is scoped to an organization you are already authorized to test with a lower-privilege token of your own; in that case the correct claim is about scope hygiene rather than a stolen credential, and the report must say which account the token belonged to.
   - Sources: <https://cwe.mitre.org/data/definitions/798.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
-- An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.
+- A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false if the recomputed digest matches the lockfile and the registry, since then the installed bytes are the published bytes and no substitution occurred on that path. It is also false if the version you flagged is simply newer than the one pinned - a version difference is an update decision, not evidence of tampering, and the digest is what settles it. And it is false as a compromise claim when the mismatch is confined to files the build never executes - a README, a test fixture, or a metadata file excluded from the install path - because the running code is unchanged; re-hash only the files actually loaded before reporting, and state which ones you excluded.
+  - Sources: <https://cwe.mitre.org/data/definitions/494.html> · <https://go.dev/ref/mod>
+- An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false if no lifecycle script executed during your install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform - and a script you never observed running proves nothing about execution. It is also false if the only effect was a compilation step confined to the package's own build directory producing the artifact the package documents it produces, which is normal packaging behaviour rather than a second delivery stage. And it is false where the observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time; trace the connection to a host that appears nowhere in the declared dependencies before treating it as exfiltration.
   - Sources: <https://cwe.mitre.org/data/definitions/506.html> · <https://docs.npmjs.com/cli/v11/using-npm/scripts>
-- A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.
-  - **Disproof:** The claim is false if the recomputed digest matches the lockfile and the registry, since then the installed bytes are the published bytes and no substitution occurred on that path. It is also false if the version you flagged is simply newer than the one pinned - a version difference is an update decision, not evidence of tampering, and the digest is what settles it. And it is false as a compromise claim when the mismatch is confined to files the build never executes - a README, a test fixture, or a metadata file excluded from the install path - because the running code is unchanged; re-hash only the files actually loaded before reporting, and state which ones you excluded.
-  - Sources: <https://cwe.mitre.org/data/definitions/494.html> · <https://go.dev/ref/mod>
-- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.
+- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window - the exposure is real but the mutation was not observed, and the report must be worded as a mutable reference rather than as a demonstrated tag move. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag, since the executed code is fixed. And it is false as an active compromise if the resolved commit's content matches the reviewed version and its signature verifies against the maintainer's key, since a moved ref that re-points at identical bytes changes nothing; verify the commit before reporting a supply-chain event rather than assuming one from the ref syntax.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/829.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
 
 ## Validation bar (how to prove it)
 
-- A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.
+- A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
 
 ## False-positive rules (when to reject it)
 
-- A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.
+- A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-10-04 13:16 — 21 diff lines
- items: 25 (supported 12), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 24 items, 11 supported, 2 FP rules, 1 chains
+> evidence: 25 items, 12 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -50,6 +50,9 @@
 - If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- Public writeup evidence for supply_chain: CI workflow -> supply chain.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/>
 - The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
```

## 2026-10-04 19:46 — 9 diff lines
- items: 25 (supported 12), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -138,6 +138,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/supply_chain/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 71 diff lines
- items: 25 (supported 22), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 25 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 25 items, 22 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -32,41 +32,41 @@
 - A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
   - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
-- After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the".
+- After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“After confirming the bypass against Log4j `2.26.1` via PoC validation and peelin”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
+- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Apache does not class allowlist bypasses like this one as product vulnerabilitie”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Chained together, they let an attacker-controlled object graph deserialize with no filter applied.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
+- Chained together, they let an attacker-controlled object graph deserialize with no filter applied.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Chained together, they let an attacker-controlled object graph deserialize with ”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".
+- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If it does not, the inner `get()` can still run unfiltered code in whatever *is*”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
+- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If you need to know which tenant an event came from, this is how. */\n| WHERE us”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - Public writeup evidence for supply_chain: CI workflow -> supply chain.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/>
-- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
+- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredO”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
+- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
-- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
+- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The receiver can still look healthy and fall back to `SimpleMessage(messageStrin”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
+- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“We are not claiming complete detection of every custom deserializer.\n\n## How t”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 
 ## Tests
```

## 2026-10-28 14:45 — 39 diff lines
- items: 21 (supported 18), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 25 items, 22 supported, 2 FP rules, 1 chains
+> evidence: 21 items, 18 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -47,16 +47,10 @@
 - If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If it does not, the inner `get()` can still run unfiltered code in whatever *is*”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If you need to know which tenant an event came from, this is how. */\n| WHERE us”) does not occur under a test that isolates that control.
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- Public writeup evidence for supply_chain: CI workflow -> supply chain.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/>
 - The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredO”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 2 duplicate row(s))_
+- The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
 - The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_
@@ -64,9 +58,6 @@
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“We are not claiming complete detection of every custom deserializer.\n\n## How t”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 
 ## Tests
```

## 2026-10-28 21:00 — 85 diff lines
- items: 28 (supported 24), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 21 items, 18 supported, 2 FP rules, 1 chains
+> evidence: 28 items, 24 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -29,12 +29,21 @@
 
 ## Techniques (what to change)
 
+- A compromised maintainer account publishing malicious versions to a namespace with many dependents propagates with no new vulnerability required.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur. If the compromised account has no write access to the namespace, the finding reduces to scope hygiene.
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- A dependency's postinstall script that reaches the network is a delivery stage, detectable by a child process fetching a remote payload detached from the original process.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if no lifecycle script executed during the install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform. It is also false if the only effect was a compilation step confined to the package's own build directory. A script whose observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time is not exfiltration.
+  - Sources: <https://cwe.mitre.org/data/definitions/506.html> · <https://docs.npmjs.com/cli/v11/using-npm/scripts>
 - A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
   - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
 - After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“After confirming the bypass against Log4j `2.26.1` via PoC validation and peelin”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
+- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag. A moved ref that re-points at identical bytes changes nothing; verify the commit before reporting.
+  - Sources: <https://cwe.mitre.org/data/definitions/829.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
 - Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Apache does not class allowlist bypasses like this one as product vulnerabilitie”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
@@ -52,7 +61,7 @@
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.
-  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The receiver can still look healthy and fall back to `SimpleMessage(messageStrin”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
@@ -65,6 +74,9 @@
 - A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the candidate is rejected by the service - a 401 or an expired-token error is a placeholder, a documentation sample, or an already-revoked key, and reporting it as a live leak is the standard false positive here. It is also false when the only place the string appears is in a test fixture, an example file, or a fixture directory inside a source tree that is excluded from the published package, which is why the extraction target must be the shipped artifact rather than the repository. And it is false as an active compromise if the credential is scoped to an organization you are already authorized to test with a lower-privilege token of your own; in that case the correct claim is about scope hygiene rather than a stolen credential, and the report must say which account the token belonged to.
   - Sources: <https://cwe.mitre.org/data/definitions/798.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
+- A supply-chain compromise is confirmed only by a mismatch between the artifact the build actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account. Absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding, not a compromise.
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026/>
 - A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false if the recomputed digest matches the lockfile and the registry, since then the installed bytes are the published bytes and no substitution occurred on that path. It is also false if the version you flagged is simply newer than the one pinned - a version difference is an update decision, not evidence of tampering, and the digest is what settles it. And it is false as a compromise claim when the mismatch is confined to files the build never executes - a README, a test fixture, or a metadata file excluded from the install path - because the running code is unchanged; re-hash only the files actually loaded before reporting, and state which ones you excluded.
   - Sources: <https://cwe.mitre.org/data/definitions/494.html> · <https://go.dev/ref/mod>
@@ -73,7 +85,7 @@
   - Sources: <https://cwe.mitre.org/data/definitions/506.html> · <https://docs.npmjs.com/cli/v11/using-npm/scripts>
 - An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window - the exposure is real but the mutation was not observed, and the report must be worded as a mutable reference rather than as a demonstrated tag move. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag, since the executed code is fixed. And it is false as an active compromise if the resolved commit's content matches the reviewed version and its signature verifies against the maintainer's key, since a moved ref that re-points at identical bytes changes nothing; verify the commit before reporting a supply-chain event rather than assuming one from the ref syntax.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/829.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
+  - Sources: <https://cwe.mitre.org/data/definitions/829.html> · <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
 
 ## Validation bar (how to prove it)
 
@@ -96,11 +108,23 @@
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.fp_rule.cve_listed_for_dependency_is_not_compromise) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
 
+## Defence bypasses
+
+- Dependency confusion: a private package registry can be bypassed when an attacker publishes a package with the same name to a public registry, and the build tooling resolves the public version because it is not explicitly configured to prefer the private source for that namespace.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the build explicitly configures the private registry with a scope mapping and the public fallback is disabled, or when the attacker's package name does not collide with any private namespace. If the build never reaches the network for the package name, or the resolution is pinned to a single authoritative source, the bypass does not occur.
+  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
+- Typosquatting: a package name one or two characters off from a popular dependency bypasses exact-name allowlisting because resolution is by string match, not semantic equivalence.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted when the dependency scanner compares the requested name against an allowlist that includes semantic variants, or when the package registry rejects the typosquatted name on creation. If the scanner is whitelist-based but compares by fuzzy match, the bypass fails.
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
+
 ## Chaining opportunities
 
 - A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install; a compromised credential with no propagation path and no agent behaviour stops at build compromise without host execution.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
+- Chain: a stolen CI credential to a self-propagating poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install. A compromised credential with no propagation path and no agent behavior stops at build compromise without host execution.
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026/>
 
 ## Rejected before you report
 
```

## 2026-10-31 06:41 — 72 diff lines
- items: 28 (supported 17), FP rules 2, chains 1, state mature

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 28 items, 24 supported, 2 FP rules, 1 chains
+> evidence: 28 items, 17 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
@@ -29,7 +29,7 @@
 
 ## Techniques (what to change)
 
-- A compromised maintainer account publishing malicious versions to a namespace with many dependents propagates with no new vulnerability required.  _(merged 1 duplicate row(s))_
+- A compromised maintainer account publishing malicious versions to a namespace with many dependents propagates with no new vulnerability required.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur. If the compromised account has no write access to the namespace, the finding reduces to scope hygiene.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - A dependency's postinstall script that reaches the network is a delivery stage, detectable by a child process fetching a remote payload detached from the original process.  _(merged 1 duplicate row(s))_
@@ -41,7 +41,7 @@
 - After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“After confirming the bypass against Log4j `2.26.1` via PoC validation and peelin”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs.  _(merged 1 duplicate row(s))_
+- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag. A moved ref that re-points at identical bytes changes nothing; verify the commit before reporting.
   - Sources: <https://cwe.mitre.org/data/definitions/829.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
 - Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.  _(merged 1 duplicate row(s))_
@@ -62,7 +62,7 @@
 - The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The payload path itself triggers the Potential Binary Masquerading via Invalid C”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
-- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_
+- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The receiver can still look healthy and fall back to `SimpleMessage(messageStrin”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
 - Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -83,13 +83,13 @@
 - An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false if no lifecycle script executed during your install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform - and a script you never observed running proves nothing about execution. It is also false if the only effect was a compilation step confined to the package's own build directory producing the artifact the package documents it produces, which is normal packaging behaviour rather than a second delivery stage. And it is false where the observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time; trace the connection to a host that appears nowhere in the declared dependencies before treating it as exfiltration.
   - Sources: <https://cwe.mitre.org/data/definitions/506.html> · <https://docs.npmjs.com/cli/v11/using-npm/scripts>
-- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.  _(merged 1 duplicate row(s))_
+- An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window - the exposure is real but the mutation was not observed, and the report must be worded as a mutable reference rather than as a demonstrated tag move. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag, since the executed code is fixed. And it is false as an active compromise if the resolved commit's content matches the reviewed version and its signature verifies against the maintainer's key, since a moved ref that re-points at identical bytes changes nothing; verify the commit before reporting a supply-chain event rather than assuming one from the ref syntax.
   - Sources: <https://cwe.mitre.org/data/definitions/829.html> · <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
 
 ## Validation bar (how to prove it)
 
-- A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.  _(merged 1 duplicate row(s))_
+- A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
 
@@ -101,7 +101,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Both halves of that statement - the publish and the consumer-side injection - are observable.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Both halves of that statement - the publish and the consumer-side injection - are observable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.validation.installed_artifact_matches_registry_publish_event) states the full boundary.
   - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
 - A convincing observation for this class is: The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code.  _(merged 1 duplicate row(s))_
@@ -119,7 +119,7 @@
 
 ## Chaining opportunities
 
-- A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.  _(merged 1 duplicate row(s))_
+- A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install; a compromised credential with no propagation path and no agent behaviour stops at build compromise without host execution.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
 - Chain: a stolen CI credential to a self-propagating poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.  _(merged 1 duplicate row(s))_
```
