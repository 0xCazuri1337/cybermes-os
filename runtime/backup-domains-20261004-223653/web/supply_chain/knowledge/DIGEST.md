# Dependency / Supply-Chain Risk

> surface: `web` · CWE: 1104 · OWASP: A06:2021
> maturity: **mature** — 25 items, 12 supported, 2 FP rules, 1 chains

Trust placed in a component, its registry or its build exceeds what was actually verified.

**Aliases:** dependency confusion, supply chain, outdated component, vulnerable dependency

## Signal

- **Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.**  
  `high_confidence` · score 0.8715 · disproved by: Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.
  sources: <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.**  
  `under_review` · score 0.7165 · disproved by: If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.
  sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>

## Technique

- **The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.**  
  `under_review` · score 0.843 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
- **The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signature and Suspicious URL as argument to Self-Signed Binary endpoint rules, as it mimics Apple naming conventions ( com.apple.* ) but does not match expected signing characteristics.**  
  `under_review` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The payload path itself triggers the Potential Binary Masquerading via Invalid Code Signat".
  sources: <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections> · <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
- **Public writeup evidence for supply_chain: CI workflow -> supply chain.**  
  `high_confidence` · score 0.821 · disproved by: Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/>
- **We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.**  
  `high_confidence` · score 0.783 · disproved by: If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
  sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
- **If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **Chained together, they let an attacker-controlled object graph deserialize with no filter applied.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **Treat it as possible gadget execution from a Java deserialization or injection path, and check whether that JVM is a log-event receiver.\n\n## Hunting for Java deserialization attacks\nHunting queries could return high signals or false positives.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Treat it as possible gadget execution from a Java deserialization or injection path, and c".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the layers on the prerequisites, we concluded this is not another Log4Shell. \n\nEither way, the detections we shared fire on what comes post-exploit for this family of vulnerabilities.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "After confirming the bypass against Log4j `2.26.1` via PoC validation and peeling back the".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>

## Test

- **An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.**  
  `high_confidence` · score 0.8265 · disproved by: The claim is false when both resolutions return the same SHA, which means the ref was stable across the observation window - the exposure is real but the mutation was not observed, and the report must be worded as a mutable reference rather than as a demonstrated tag move. It is also false if the consumer already pins a full-length commit SHA and merely carries a comment naming a friendly tag, since the executed code is fixed. And it is false as an active compromise if the resolved commit's content matches the reviewed version and its signature verifies against the maintainer's key, since a moved ref that re-points at identical bytes changes nothing; verify the commit before reporting a supply-chain event rather than assuming one from the ref syntax.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/829.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- **A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.**  
  `high_confidence` · score 0.8105 · disproved by: The claim is false when the candidate is rejected by the service - a 401 or an expired-token error is a placeholder, a documentation sample, or an already-revoked key, and reporting it as a live leak is the standard false positive here. It is also false when the only place the string appears is in a test fixture, an example file, or a fixture directory inside a source tree that is excluded from the published package, which is why the extraction target must be the shipped artifact rather than the repository. And it is false as an active compromise if the credential is scoped to an organization you are already authorized to test with a lower-privilege token of your own; in that case the correct claim is about scope hygiene rather than a stolen credential, and the report must say which account the token belonged to.
  sources: <https://cwe.mitre.org/data/definitions/798.html> · <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- **An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.**  
  `high_confidence` · score 0.8105 · disproved by: The claim is false if no lifecycle script executed during your install - because the install ran with --ignore-scripts, in a mode that suppresses them, or because the script's condition did not match your platform - and a script you never observed running proves nothing about execution. It is also false if the only effect was a compilation step confined to the package's own build directory producing the artifact the package documents it produces, which is normal packaging behaviour rather than a second delivery stage. And it is false where the observed outbound connection is to a registry or CDN the package's own dependency tree legitimately resolves at install time; trace the connection to a host that appears nowhere in the declared dependencies before treating it as exfiltration.
  sources: <https://cwe.mitre.org/data/definitions/506.html> · <https://docs.npmjs.com/cli/v11/using-npm/scripts>
- **A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.**  
  `high_confidence` · score 0.8105 · disproved by: The claim is false if the recomputed digest matches the lockfile and the registry, since then the installed bytes are the published bytes and no substitution occurred on that path. It is also false if the version you flagged is simply newer than the one pinned - a version difference is an update decision, not evidence of tampering, and the digest is what settles it. And it is false as a compromise claim when the mismatch is confined to files the build never executes - a README, a test fixture, or a metadata file excluded from the install path - because the running code is unchanged; re-hash only the files actually loaded before reporting, and state which ones you excluded.
  sources: <https://cwe.mitre.org/data/definitions/494.html> · <https://go.dev/ref/mod>

## Validation

- **A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.**  
  `high_confidence` · score 0.899 · disproved by: Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## Fp Rule

- **A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.**  
  `high_confidence` · score 0.854 · disproved by: Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
  sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## Evidence

- **A convincing observation for this class is: The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code.**  
  `high_confidence` · score 0.838 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.fp_rule.cve_listed_for_dependency_is_not_compromise) states the full boundary.
  sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
- **A convincing observation for this class is: Both halves of that statement - the publish and the consumer-side injection - are observable.**  
  `high_confidence` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (supply_chain.validation.installed_artifact_matches_registry_publish_event) states the full boundary.
  sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## Chain Link

- **A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.**  
  `high_confidence` · score 0.899 · disproved by: Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install; a compromised credential with no propagation path and no agent behaviour stops at build compromise without host execution.
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## False-positive rules

- **Hypothesis:** A CVE recorded against a third-party library in the dependency tree means the build was compromised by a supply-chain attack.
  - **Invalidated by:** The resolved artifact matched the registry-published hash and no unauthorized publish, yank, or token-scope event existed on the account; the CVE described a defect in the legitimate release, which is a patch, not a compromise.
  - **Rule:** A CVE in a dependency scan is a patchability finding, not a supply-chain compromise. Compromise requires either a byte-level mismatch between the resolved artifact and the registry-published one, or an unauthorized publish event on the package account. Check both before filing.

## Related classes (via chains)

- `exposed_rmm` Remote Monitoring and Management Abuse (3 chains)
