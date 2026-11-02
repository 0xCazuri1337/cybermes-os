# Dependency / Supply-Chain Risk

## Definition

Trust placed in a component, its registry or its build exceeds what was actually verified.

- **CWE:** 1104
- **OWASP:** A06:2021
- **Surface:** web
- **Aliases:** ["dependency confusion", "supply chain", "outdated component", "vulnerable dependency"]

Canonical home for `supply_chain`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

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

## Exploitation

**A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.**

Registry publish tokens are bearer credentials for a package namespace. Holding one means the attacker can release a new version that every downstream consumer installs by default, so the blast radius grows with no new attack. This changes how a token leak is scoped: the finding is not one exposed token but an attacker-controlled package namespace until the token is rotated and the account secured. Defensive review should look for provenance binding, publish-time attestation and short token lifetime rather than assuming rotation is immediate.

*Disproof:* If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.

## Variations

Not yet researched.

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

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/1104.html>
- **elastic.co** (research)
  - <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
  - <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
- **stepsecurity.io** (writeup)
  - <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
- **unit42.paloaltonetworks.com** (writeup)
  - <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/>
- **welivesecurity.com** (report)
  - <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
