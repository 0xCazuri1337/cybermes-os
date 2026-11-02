# Methodology — NTLM Authentication Weaknesses

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class ad_ntlm --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

**References.** CWE-294

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**

NTLM is the default fallback client-server authentication protocol inside Windows networks, so every mixed or downlevel estate produces constant NTLM exchanges that have nothing to do with an adversary. The prerequisite before any NTLM-class assertion is a baseline: which hosts normally speak NTLM, to which services, from which source addresses, and with which accounts. Post-attack work that leans on Kerberos, DNS queries, share access or generic domain-infrastructure protocols is described as virtually indistinguishable from legitimate traffic, and NTLM sits in the same category because the protocol handshake itself carries no adversary marker. Only after the baseline exists does a change - a new NTLM-speaking host, a new target service, a new source for a given host - become testable rather than an artefact of estate age.

- *Disproof:* If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
- *Evidence:* high_confidence — [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.**

The relay primitive is that NTLM's proof is possession of a response keyed on a shared secret and a server challenge — not a property of the TLS channel the client believes it is on. A client induced to authenticate to an attacker-controlled listener produces a response for a challenge the attacker chose; that response is then presented to a victim service, which validates it because it cannot tell the request did not arrive over the intended channel. Two ways this works in practice: capture-and-relay, where the adversary sits in the authentication path; and coercion, where the adversary induces the outbound authentication. Both are independent of hash cracking. The bound on the whole class is channel binding plus mandatory signing on the target service: if every service that accepts NTLM also requires signing, the relayed response has no valid signature and the exchange fails.

- *Disproof:* If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1557/001/); [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a ad_ntlm finding until it is distinguished from the adjacent behaviour this class also covers. "An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts..." and "NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts...

Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "NTLM authentication traffic cannot be treated as an anomaly until a pe" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1557/001/); [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft)

**One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.**

The observation is a single outbound SMB connect from a workstation to an external IP followed by an NTLM negotiate/challenge/authenticate exchange, which is what coercion looks like: a specially crafted malicious script can coerce the victim machine to connect back to the attack system using SMB and authenticate. Because coercion is the whole mechanism, the client-side exchange is identical whether the server harvests the response or merely receives it and drops it, and the server has no obligation to relay anything. A single Type-3 therefore proves the client was made to authenticate, not that the credential material was captured and reused. The benign reading is an Outlook message or Office document containing a UNC path. The discriminating evidence lives on the attacking server, not the client: in a real capture the server shows the open-source Impacket toolkit's default NTLM server challenge of sixteen a characters and the toolkit's default SMB GUID, and practices that are uncommon in standard SMB servers. Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure. Escalate only when the relay fingerprint or a second authenticated session exists.

- *Disproof:* The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/); [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
