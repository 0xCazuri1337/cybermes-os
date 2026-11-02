# Methodology — Dependency / Supply-Chain Risk

> Derived from 12 verified items. Regenerate with `python -m wks.methodgen --class supply_chain --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**Public writeup evidence for supply_chain: CI workflow -> supply chain.**

HARVESTED FROM bugbountydaily RSS -> https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/
Reason it matters: CI workflow -> supply chain.

The gh CLI accepts URLs as positional arguments, so a prompt injection payload can instruct Claude to embed secret values in the URL path or query parameters (e.g., gh issue view https://example.com/ ), sending the secrets to an attacker-controlled server.

- *Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [flatt.tech](https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/)

**A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.**

Registry publish tokens are bearer credentials for a package namespace. Holding one means the attacker can release a new version that every downstream consumer installs by default, so the blast radius grows with no new attack. This changes how a token leak is scoped: the finding is not one exposed token but an attacker-controlled package namespace until the token is rotated and the account secured. Defensive review should look for provenance binding, publish-time attestation and short token lifetime rather than assuming rotation is immediate.

- *Disproof:* If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
- *Evidence:* high_confidence — [stepsecurity.io](https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.**

Two independent checks, because either alone produces false positives. Check one, the artifact comparison: for the exact version string your lockfile or deployed image resolved, compare the bytes or the lockfile integrity hash against the hash the registry publishes for that version, and record whether they match. A match means the bytes you ran are the bytes the maintainer published, which eliminates the injected-payload case entirely - you cannot be running trojanized code that the registry does not carry. Check two, the publish event: look for a publish, yank, or token-scope event on the package account that occurred outside the maintainer's normal release window, or a version whose publish timestamp falls inside an incident window. The real axios case shows what corroboration looks like in practice: the lead maintainer's compromised credentials were used to publish malicious versions of a library with over 100 million weekly downloads, the injected code reached affected systems, and it was detected and removed. Both halves of that statement - the publish and the consumer-side injection - are observable. When your hash matches and no anomalous publish exists, the finding is a CVE to patch, and the regression check is to rerun the hash comparison on every build so a future mismatch is caught where it appears rather than inferred from a scan.

- *Disproof:* Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.
- *Evidence:* high_confidence — [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/); [welivesecurity.com](https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.**

The lookalike: a dependency scan returns a CVE for a package you depend on, the CVE text describes trojanized code injected into that library, and it is filed as a supply-chain compromise of your application. It is not. CWE-1104 is about relying on unmaintained components and the resulting difficulty of fixing significant bugs - that is a hygiene and patchability finding, not proof that anyone reached your build. The compromise class is separate and has a distinct observable event: the registry account or maintainer credential is used to publish a malicious version and consumers who install it receive the trojanized code. The axios operation ESET documented is exactly that - the lead maintainer's compromised credentials were used to publish malicious versions of a library with over 100 million weekly downloads, injecting trojanized code into affected systems before detection and removal. Note also that the rising count of registered vulnerabilities in third-party software is driven largely by AI-assisted discovery, which increases the number of CVEs without any increase in compromises. Discriminator: did the artifact your build resolved differ from the upstream published artifact? If the installed bytes match the published release and no unauthorized publish event exists on the package, you have a CVE to patch, not a compromise to report.

- *Disproof:* Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1104.html); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/); [welivesecurity.com](https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.**

The chain here is self-propagating, which is what makes it worth assembling rather than reporting as three findings. The egress half: a CI runner able to reach arbitrary network destinations will hand its credentials to whatever answers, so the trust boundary is the runner's network position, not its repository permissions. The propagation half: a stolen package publish token lets an attacker ship further malicious versions from the compromised account, so one credential yields unbounded downstream delivery rather than a single payload. The delivery half: attacks that avoid embedding malicious logic in the primary payload are hard to spot by content inspection, which is exactly what makes a build-time compromise survive review. What converts all three into impact is the installed agent. Securelist's GPO work is the concrete instance of the delivery stage: rather than deploying an encryptor, the actor abused the victim's Active Directory policy infrastructure, and group policies are processed in a trusted, high-privilege environment, ensuring persistence because endpoint cleanup is not enough to remove them - the remediation plan's first priority is removing the source GPOs, since until that is done endpoint cleanup is ineffective because the next policy refresh re-infects cleaned machines. That is the whole chain in one property: the delivery mechanism re-executes on a schedule you do not control, so host-level remediation cannot outrun it.

- *Disproof:* Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install; a compromised credential with no propagation path and no agent behaviour stops at build compromise without host execution.
- *Evidence:* high_confidence — [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/); [welivesecurity.com](https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
