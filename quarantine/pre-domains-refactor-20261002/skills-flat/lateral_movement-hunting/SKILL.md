---
name: lateral_movement-hunting
description: Use when hunting Lateral Movement in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Lateral Movement — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-284 · OWASP —
> evidence: 5 items, 5 supported, 4 FP rules, 2 chains
> maturity: **researching** — missing: items

Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.

**Also called:** lateral movement, move laterally, pivot, pivoting, east west movement, internal movement


## Prerequisites (do not start without these)

- Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.
  - **Disproof:** If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Techniques (what to change)

- Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.
  - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.
  - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
  - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>

## False-positive rules (when to reject it)

- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.
  - **Disproof:** If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.
  - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>

## Rejected before you report

- **Lateral movement to a privileged host: a domain admin session was present on a machine my foothold account could reach**
  - Killed by: the session was the account owner operating their own account interactively from their normal station; real operators likewise reuse long-lived legitimate tickets to gain legitimate access rather than minting new authentications
  - Rule: an existing privileged session on a reachable host is a lookalike; it becomes evidence only when the ticket was extracted or replayed from another host rather than issued interactively to its owner
- **A remote logon to an administrative share on a peer host is evidence of lateral movement.**
  - Killed by: The logon used valid domain credentials in the approved remote administration tooling and the identical pattern recurs across many source hosts on a scheduled cycle, so it is the sanctioned access path rather than a pivot; no credential was reused from memory or dump.
  - Rule: A remote administrative session carrying valid credentials in the sanctioned tool is expected ER activity, not lateral movement. Lateral movement requires either a credential the session could not legitimately hold, or a protocol path outside the approved administration profile.

## Chains to

- `exposed_services` (2 shared chain(s))
- `smb` (1 shared chain(s))
- `internal_recon` (1 shared chain(s))
- `info_disclosure` (1 shared chain(s))
- `ad_enumeration` (1 shared chain(s))

---
Full class document: `skills/Network + AD/lateral_movement/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
