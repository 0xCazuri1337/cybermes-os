---
name: supply_chain-hunting
description: Use when hunting Dependency / Supply-Chain Risk in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Dependency / Supply-Chain Risk — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 1104 · OWASP A06:2021
> evidence: 6 items, 6 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

Trust placed in a component, its registry or its build exceeds what was actually verified.

**Also called:** dependency confusion, supply chain, outdated component, vulnerable dependency


## Recon signals (where to look)

- A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.
  - **Disproof:** If the runner holds no credentials in its environment, or already denies all non-essential egress, reachability does not translate into credential exposure.
  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
- Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.
  - **Disproof:** Build pipelines that block post-install scripts and never permit a package install to reach the network would refute the claim as a hunting premise.
  - Sources: <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/> · <https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections>

## Techniques (what to change)

- A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.
  - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
  - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>

## Validation bar (how to prove it)

- A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.
  - **Disproof:** Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.
  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## False-positive rules (when to reject it)

- A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.
  - **Disproof:** Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
  - Sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## Chaining opportunities

- A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.
  - **Disproof:** Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install; a compromised credential with no propagation path and no agent behaviour stops at build compromise without host execution.
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>

## Rejected before you report

- **A CVE recorded against a third-party library in the dependency tree means the build was compromised by a supply-chain attack.**
  - Killed by: The resolved artifact matched the registry-published hash and no unauthorized publish, yank, or token-scope event existed on the account; the CVE described a defect in the legitimate release, which is a patch, not a compromise.
  - Rule: A CVE in a dependency scan is a patchability finding, not a supply-chain compromise. Compromise requires either a byte-level mismatch between the resolved artifact and the registry-published one, or an unauthorized publish event on the package account. Check both before filing.

## Chains to

- `exposed_rmm` (3 shared chain(s))

---
Full class document: `skills/Web/supply_chain/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
