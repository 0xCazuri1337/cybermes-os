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
