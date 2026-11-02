# Lateral Movement

## Definition

Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.

- **CWE:** CWE-284
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["lateral movement", "move laterally", "pivot", "pivoting", "east west movement", "internal movement"]

Canonical home for `lateral_movement`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.**

Windows lateral movement means navigating to and controlling remote systems, which is by definition a second step after gaining initial access on a first. Three things must be true before the claim is testable: a foothold on host A, a credential or session on A that authenticates elsewhere, and a reachable target B. Without all three, a network trace showing A talking to B is inventory or management traffic, not movement. The corollary matters for hunting: 'host A authenticated to host B' is a signal, not a finding, and it becomes a finding only once you can show the authentication used material that the operator of A should not have had, or was replayed from A without a legitimate session.

*Disproof:* If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.**

The technique has two ordered halves and both must be observed. The first half is confirming the relay server rather than assuming it: indications supporting capture theory include artifacts on the SMB servers pointing towards the use of the open-source Impacket toolkit, identifiable by the default NTLM server challenge of sixteen a characters and the default GUID observed in the traffic, practices uncommon in standard SMB servers. The second half is what the session buys. A successful relay attack against an SMB server establishes a session, so the attacker's next steps depend on the access the relay victim has: they could gain access to the C$ or ADMIN$ share on the relay target, dump LSA secrets from Remote Registry, including the computer account password, or move laterally via the Service Control Manager. The computer account password is the pivot that matters, because it is a domain credential that authenticates as the machine account without a user password. A common higher-order variant coerces authentication from an SCCM site server and relays it to the SCCM database server to take over the entire hierarchy, so the target selection is protocol-shaped rather than address-shaped. Detection should therefore pair the relay fingerprint on the external server with an authenticated admin-share session and a Remote Registry read on the target.

*Disproof:* The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.

**Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.**

With a set of valid domain credentials, the set of hosts reachable and the protocols each one offers is what defines the movement surface — remote services including SSH and RDP are the standard carriers. Two properties make the choice non-arbitrary. First, legitimate administrative tooling already uses these same protocols, so a lateral move over SMB, WinRM or SSH is indistinguishable from software deployment at the protocol layer; MITRE notes that using legitimate credentials with native network and OS tools may be stealthier than installing an adversary tool. Second, some remote services also carry execution (WinRM, SMB), which collapses movement and execution into one step. That makes reachability inventory the prerequisite for assessing the whole class, and it makes an unexpected management protocol on a host the finding worth escalating.

*Disproof:* If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ad-enum-to-kerberoast-to-lateral-execution` — Directory enumeration to SPN enumeration to kerberoasted service account to lateral execution (goal: `domain_wide_lateral_movement`)
- `reachable-admin-service-to-relayed-credential-to-lateral` — Policy-violating administrative service reachability to relayed server credentials to lateral movement (goal: `credential_theft_and_lateral`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.**

The classic false positive is opportunistic reuse. An assessor with a foothold finds a host where their account has local administrative rights, notices a domain administrator already has a session there, and treats that as proof the admin was reached. It is not: administrators log into servers they administer as themselves, and an active session is the expected state of a managed estate. The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication. The session becomes evidence only when the ticket was extracted or replayed from your foothold host rather than issued to the admin interactively.

*Disproof:* If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.

**A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.**

The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement. The technique and the artefacts are byte-for-byte identical whether the operator is an attacker or an incident responder who was issued the same credential, and WMI in particular is used routinely for benign purposes, so malicious remote execution blends into legitimate remote execution by construction. The one question that decides the finding is not what was executed but where the credential came from: if it was observed being stolen in the same engagement, this is the second half of a credential-access chain; if it was issued to the tester, it is expected activity. This rule rejects the technique artefact and holds the report to that provenance question.

*Disproof:* The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
**Hypothesis:** Lateral movement to a privileged host: a domain admin session was present on a machine my foothold account could reach
- Invalidated by: the session was the account owner operating their own account interactively from their normal station; real operators likewise reuse long-lived legitimate tickets to gain legitimate access rather than minting new authentications
- **Rejection rule:** an existing privileged session on a reachable host is a lookalike; it becomes evidence only when the ticket was extracted or replayed from another host rather than issued interactively to its owner

**Hypothesis:** A remote logon to an administrative share on a peer host is evidence of lateral movement.
- Invalidated by: The logon used valid domain credentials in the approved remote administration tooling and the identical pattern recurs across many source hosts on a scheduled cycle, so it is the sanctioned access path rather than a pivot; no credential was reused from memory or dump.
- **Rejection rule:** A remote administrative session carrying valid credentials in the sanctioned tool is expected ER activity, not lateral movement. Lateral movement requires either a credential the session could not legitimately hold, or a protocol path outside the approved administration profile.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1021/>
- **helpnetsecurity.com** (blog)
  - <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md>
  - <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4251.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
