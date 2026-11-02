# NTLM Authentication Weaknesses

## Definition

An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

- **CWE:** CWE-294
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["ntlm", "ntlmv1", "relay", "ntlm relay", "name piping", "named pipe", "nbns spoofing", "smb relay", "responder"]

Canonical home for `ad_ntlm`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**

NTLM is the default fallback client-server authentication protocol inside Windows networks, so every mixed or downlevel estate produces constant NTLM exchanges that have nothing to do with an adversary. The prerequisite before any NTLM-class assertion is a baseline: which hosts normally speak NTLM, to which services, from which source addresses, and with which accounts. Post-attack work that leans on Kerberos, DNS queries, share access or generic domain-infrastructure protocols is described as virtually indistinguishable from legitimate traffic, and NTLM sits in the same category because the protocol handshake itself carries no adversary marker. Only after the baseline exists does a change - a new NTLM-speaking host, a new target service, a new source for a given host - become testable rather than an artefact of estate age.

*Disproof:* If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.**

The relay primitive is that NTLM's proof is possession of a response keyed on a shared secret and a server challenge — not a property of the TLS channel the client believes it is on. A client induced to authenticate to an attacker-controlled listener produces a response for a challenge the attacker chose; that response is then presented to a victim service, which validates it because it cannot tell the request did not arrive over the intended channel. Two ways this works in practice: capture-and-relay, where the adversary sits in the authentication path; and coercion, where the adversary induces the outbound authentication. Both are independent of hash cracking. The bound on the whole class is channel binding plus mandatory signing on the target service: if every service that accepts NTLM also requires signing, the relayed response has no valid signature and the exchange fails.

*Disproof:* If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.**

The observation is a single outbound SMB connect from a workstation to an external IP followed by an NTLM negotiate/challenge/authenticate exchange, which is what coercion looks like: a specially crafted malicious script can coerce the victim machine to connect back to the attack system using SMB and authenticate. Because coercion is the whole mechanism, the client-side exchange is identical whether the server harvests the response or merely receives it and drops it, and the server has no obligation to relay anything. A single Type-3 therefore proves the client was made to authenticate, not that the credential material was captured and reused. The benign reading is an Outlook message or Office document containing a UNC path. The discriminating evidence lives on the attacking server, not the client: in a real capture the server shows the open-source Impacket toolkit's default NTLM server challenge of sixteen a characters and the toolkit's default SMB GUID, and practices that are uncommon in standard SMB servers. Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure. Escalate only when the relay fingerprint or a second authenticated session exists.

*Disproof:* The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1557/001/>
- **helpnetsecurity.com** (blog)
  - <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
