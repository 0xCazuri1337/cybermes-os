# Methodology — Lateral Movement

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class lateral_movement --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.

**References.** CWE-284

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.**

Windows lateral movement means navigating to and controlling remote systems, which is by definition a second step after gaining initial access on a first. Three things must be true before the claim is testable: a foothold on host A, a credential or session on A that authenticates elsewhere, and a reachable target B. Without all three, a network trace showing A talking to B is inventory or management traffic, not movement. The corollary matters for hunting: 'host A authenticated to host B' is a signal, not a finding, and it becomes a finding only once you can show the authentication used material that the operator of A should not have had, or was replayed from A without a legitimate session.

- *Disproof:* If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.**

The technique has two ordered halves and both must be observed. The first half is confirming the relay server rather than assuming it: indications supporting capture theory include artifacts on the SMB servers pointing towards the use of the open-source Impacket toolkit, identifiable by the default NTLM server challenge of sixteen a characters and the default GUID observed in the traffic, practices uncommon in standard SMB servers. The second half is what the session buys. A successful relay attack against an SMB server establishes a session, so the attacker's next steps depend on the access the relay victim has: they could gain access to the C$ or ADMIN$ share on the relay target, dump LSA secrets from Remote Registry, including the computer account password, or move laterally via the Service Control Manager. The computer account password is the pivot that matters, because it is a domain credential that authenticates as the machine account without a user password. A common higher-order variant coerces authentication from an SCCM site server and relays it to the SCCM database server to take over the entire hierarchy, so the target selection is protocol-shaped rather than address-shaped. Detection should therefore pair the relay fingerprint on the external server with an authenticated admin-share session and a Remote Registry read on the target.

- *Disproof:* The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/); [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft)

**Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.**

With a set of valid domain credentials, the set of hosts reachable and the protocols each one offers is what defines the movement surface — remote services including SSH and RDP are the standard carriers. Two properties make the choice non-arbitrary. First, legitimate administrative tooling already uses these same protocols, so a lateral move over SMB, WinRM or SSH is indistinguishable from software deployment at the protocol layer; MITRE notes that using legitimate credentials with native network and OS tools may be stealthier than installing an adversary tool. Second, some remote services also carry execution (WinRM, SMB), which collapses movement and execution into one step. That makes reachability inventory the prerequisite for assessing the whole class, and it makes an unexpected management protocol on a host the finding worth escalating.

- *Disproof:* If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4251.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.**

The classic false positive is opportunistic reuse. An assessor with a foothold finds a host where their account has local administrative rights, notices a domain administrator already has a session there, and treats that as proof the admin was reached. It is not: administrators log into servers they administer as themselves, and an active session is the expected state of a managed estate. The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication. The session becomes evidence only when the ticket was extracted or replayed from your foothold host rather than issued to the admin interactively.

- *Disproof:* If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

**A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.**

The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement. The technique and the artefacts are byte-for-byte identical whether the operator is an attacker or an incident responder who was issued the same credential, and WMI in particular is used routinely for benign purposes, so malicious remote execution blends into legitimate remote execution by construction. The one question that decides the finding is not what was executed but where the credential came from: if it was observed being stolen in the same engagement, this is the second half of a credential-access chain; if it was issued to the tester, it is expected activity. This rule rejects the technique artefact and holds the report to that provenance question.

- *Disproof:* The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md); [redcanary.com](https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/)

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
