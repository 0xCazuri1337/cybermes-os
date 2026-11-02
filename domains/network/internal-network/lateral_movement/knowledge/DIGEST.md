# Lateral Movement

> surface: `net` · CWE: CWE-284 · OWASP: —
> maturity: **mature** — 12 items, 7 supported, 3 FP rules, 2 chains

Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.

**Aliases:** lateral movement, move laterally, pivot, pivoting, east west movement, internal movement

## Prerequisite

- **Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.**  
  `high_confidence` · score 0.8355 · disproved by: If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Technique

- **Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.**  
  `high_confidence` · score 0.844 · disproved by: The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
  sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- **Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.**  
  `under_review` · score 0.834 · disproved by: If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
  sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>

## Test

- **WMI lateral movement is demonstrated by remote WMI execution on the destination, not by the presence of the WMI service; WMI is both a local and remote management interface, so remote use is a legitimate administrative pattern as well as an adversary technique.**  
  `high_confidence` · score 0.893 · disproved by: Management tools and endpoint agents routinely use remote WMI. A wmiprvse.exe process or a port 135 or 5985 connection is not a finding without a state-changing operation tied to the engagement.
  sources: <https://attack.mitre.org/techniques/T1047/> · <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/>
- **To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication.**  
  `under_review` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **An open WinRM port is not lateral movement; WinRM is a protocol for interacting with a remote system, and the finding requires an authenticated operation that runs a command, modifies the registry, or changes a service on the destination.**  
  `high_confidence` · score 0.8415 · disproved by: WinRM is a standard Windows management service. A listener on 5985 is common in managed fleets and is not, by itself, evidence of compromise. The operation and its principal must be tied to the engagement and outside the destination baseline.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- **Lateral movement is proven by a successful action on a second host using credentials obtained in the engagement, not by the protocol used; SSH, RDP, SMB, WMI, and WinRM are interchangeable carriers once reachability and credentials exist.**  
  `under_review` · score 0.814 · disproved by: The movement finding fails when the supposed destination action used a pre-existing tester account with no engagement-derived credential, when the action ran only on the original host, or when the destination was never reached and only a protocol banner was observed.
  sources: <https://attack.mitre.org/techniques/T1021/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **PsExec-style SMB lateral movement is demonstrated by remote process execution on the destination, not by an SMB session or a share mount; PsExec executes processes on other systems over an authenticated SMB/RPC path.**  
  `high_confidence` · score 0.814 · disproved by: A benign backup, software deployment, or administrative script can create an SMB session and a remote service. Reject the finding unless the remote execution used credentials obtained in the engagement and the action is outside the destination's normal administrative baseline.
  sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://learn.microsoft.com/en-us/sysinternals/downloads/psexec>
- **An exposed RDP port is not lateral movement; RDP/RDS expands access only when the service is enabled and allows access to accounts with known credentials, so the finding requires an authenticated remote session or action.**  
  `high_confidence` · score 0.814 · disproved by: RDP is a normal administrative and remote-work service. An open 3389 port, a certificate, or a logon screen is not evidence of unauthorized movement; the authenticated session and the credential provenance are the finding.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-rds>

## Fp Rule

- **Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.**  
  `under_review` · score 0.8715 · disproved by: If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.**  
  `high_confidence` · score 0.86 · disproved by: The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
  sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.**  
  `under_review` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity) states the full boundary.
  sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>

## False-positive rules

- **Hypothesis:** Lateral movement to a privileged host: a domain admin session was present on a machine my foothold account could reach
  - **Invalidated by:** the session was the account owner operating their own account interactively from their normal station; real operators likewise reuse long-lived legitimate tickets to gain legitimate access rather than minting new authentications
  - **Rule:** an existing privileged session on a reachable host is a lookalike; it becomes evidence only when the ticket was extracted or replayed from another host rather than issued interactively to its owner

- **Hypothesis:** A remote logon to an administrative share on a peer host is evidence of lateral movement.
  - **Invalidated by:** The logon used valid domain credentials in the approved remote administration tooling and the identical pattern recurs across many source hosts on a scheduled cycle, so it is the sanctioned access path rather than a pivot; no credential was reused from memory or dump.
  - **Rule:** A remote administrative session carrying valid credentials in the sanctioned tool is expected ER activity, not lateral movement. Lateral movement requires either a credential the session could not legitimately hold, or a protocol path outside the approved administration profile.

## Related classes (via chains)

- `exposed_services` Exposed Remote Services (2 chains)
- `smb` SMB/CIFS Abuse (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `info_disclosure` Information Disclosure (1 chains)
- `ad_enumeration` Active Directory Enumeration (1 chains)
