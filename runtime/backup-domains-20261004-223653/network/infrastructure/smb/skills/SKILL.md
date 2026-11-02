---
name: smb-hunting
description: Use when hunting SMB/CIFS Abuse in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# SMB/CIFS Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-732 · OWASP —
> evidence: 10 items, 9 supported, 4 FP rules, 1 chains
> maturity: **researching** — missing: items

SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.

**Also called:** smb, cifs, null session, guest session, smb signing, smb1, named pipe coercion, share enumeration, psexec


## Techniques (what to change)

- Anonymous or guest access to an SMB share, and the enumeration that reveals it, is the usual route to credentials or a file drop on a Windows target.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the share requires authentication and rejects guest/anonymous sessions, and no share permits a write, so the share yields neither credentials nor a file drop.
  - Sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/04.%20Exploitation/19.%20Attacking%20Common%20Services/Attacking%20Common%20Services.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Footprinting%20Services.md>
- SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.
  - Sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://www.rfc-editor.org/rfc/rfc1002.html>

## Tests

- To decide this case, observe: Discard when the tester reported that authentication succeeded but no session could be used: without the shared session key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default.  _(merged 1 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (smb.fprule.signing_required_ends_relay) states the full boundary.
  - Sources: <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

## Validation bar (how to prove it)

- A relay finding is bounded by the negotiated signing state, so the validation that separates a real relay path from a non-finding is a differential test of the same request with and without a valid signature, not the mere presence of an SMB listener.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the server accepts unsigned or wrongly-signed SMB sessions on the relevant share, the differential shows no rejection and the relay ceiling is not established by configuration alone; conversely if the server enforces signing on both ends, the relay link is closed and the finding does not hold regardless of listener exposure.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>

## False-positive rules (when to reject it)

- Hidden administrative shares (C$, ADMIN$, IPC$) answering on tcp/445 inside the corporate network are the DEFAULT Windows configuration, not an exposed-share vulnerability; do not file their existence as a finding unless the share is reachable from outside the assessed scope boundary or is created outside the default set (a custom share, a webroot share, or a share added by an operator).  _(merged 1 duplicate row(s))_
  - **Disproof:** The same share is reachable from a host outside the assessed scope boundary (for example the public internet or a partner network), or the share name is not one of the Windows default administrative shares - a custom data share, an IIS webroot such as \inetpub\wwwroot, or a share created by an operator during deployment - which means somebody chose to expose it.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.
  - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/>
- SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.
  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- When the target enforces SMB signing the relay stops at authentication, so a signed-session failure is not a broken-signing finding.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong where CVE-2019-1019 style session-key retrieval was possible, since then signing provides no protection against relay.
  - Sources: <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

## Evidence requirements

- A convincing observation for this class is: The observable that triggers this false positive is a share enumeration against an internal Windows host returning C$, ADMIN$ and IPC$ - names that appear on essentially every domain-joined machine because the Lanman Server enables them so that administrators and management software can drive hosts remotely over SMB.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smb.fp_rule.admin_shares_present_is_default_windows) states the full boundary.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>

## Chaining opportunities

- A server that initiates an outbound SMB connect to an attacker-chosen host will answer that host's challenge with its own NTLM credentials, so a force-authentication primitive converts an unauthenticated connection into a relayable credential without the attacker ever holding a password.  _(merged 1 duplicate row(s))_
  - **Disproof:** If SMB signing is mandatory on the first connection, or the target refuses outbound SMB to untrusted peers, or channel binding pins the second service to a TLS channel the attacker does not hold, no NTLM response is emitted or accepted and the relay link has nothing to work with.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening> · <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>

## Rejected before you report

- **SMB-based lateral movement: unexpected SMB sessions from a host that was not an admin workstation**
  - Killed by: the portproxy entry was a sanctioned administrative redirect with a documented owner, and the SMB peer was that application's backend; the toolkit was also living off the land by design, using built-in SMB/WMI/WinRM
  - Rule: an SMB session from a management or tooling host is not lateral movement until the redirection and the protocol abuse are shown to lack a sanctioned administrative owner

## Chains to

- `exposed_services` (2 shared chain(s))
- `lateral_movement` (1 shared chain(s))


## Hunt procedure

1. Test signing requirements and share enumeration together; an unsigned session plus a readable share is the finding.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/infrastructure/smb/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
