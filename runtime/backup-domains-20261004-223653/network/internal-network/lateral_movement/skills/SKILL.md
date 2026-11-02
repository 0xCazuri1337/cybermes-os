---
name: lateral_movement-hunting
description: Use when hunting Lateral Movement in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Lateral Movement — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-284 · OWASP —
> evidence: 17 items, 5 supported, 3 FP rules, 2 chains
> maturity: **mature**

Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.

**Also called:** lateral movement, move laterally, pivot, pivoting, east west movement, internal movement


## Prerequisites (do not start without these)

- Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Techniques (what to change)

- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.  _(merged 1 duplicate row(s))_
  - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
  - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>
- Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.  _(merged 1 duplicate row(s))_
  - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>

## Tests

- To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## False-positive rules (when to reject it)

- A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.  _(merged 1 duplicate row(s))_
  - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Evidence requirements

- A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity) states the full boundary.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>

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


## Hunt procedure

1. Map one hop at a time from a foothold you already hold; record the reachable path, do not execute the pivot.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/internal-network/lateral_movement/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
