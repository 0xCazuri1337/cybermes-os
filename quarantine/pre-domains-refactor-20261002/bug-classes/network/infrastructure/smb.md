# SMB/CIFS Abuse

## Definition

SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.

- **CWE:** CWE-732
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["smb", "cifs", "null session", "guest session", "smb signing", "smb1", "named pipe coercion", "share enumeration", "psexec"]

Canonical home for `smb`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.**

Because SMB carries file access, remote procedure calls and remote execution over one authenticated session, a share write is a staging step rather than an endpoint — the file lands and something else runs it. ATT&CK names the executions that ride the same authenticated SMB/RPC session: scheduled task, service execution and WMI. That changes the priority order for hunting: a host that writes a file to a remote administrative share and a host that then connects to create a service on that target are one incident, not two. NetBIOS is the naming and transport layer underneath, which is why the original NetBIOS-over-TCP specification still matters for understanding why a name resolution answer can direct a client to the adversary's listener. The practical control is signing: where SMB signing is not required, an intercepted or coerced authentication is reusable; where it is required, the relay and coercion variants close even though the file transfer does not.

*Disproof:* If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `reachable-admin-service-to-relayed-credential-to-lateral` — Policy-violating administrative service reachability to relayed server credentials to lateral movement (goal: `credential_theft_and_lateral`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Hidden administrative shares (C$, ADMIN$, IPC$) answering on tcp/445 inside the corporate network are the DEFAULT Windows configuration, not an exposed-share vulnerability; do not file their existence as a finding unless the share is reachable from outside the assessed scope boundary or is created outside the default set (a custom share, a webroot share, or a share added by an operator).**

The observable that triggers this false positive is a share enumeration against an internal Windows host returning C$, ADMIN$ and IPC$ - names that appear on essentially every domain-joined machine because the Lanman Server enables them so that administrators and management software can drive hosts remotely over SMB. Nothing was misconfigured and nothing was disclosed beyond what the host must expose to operate inside a corporate network. The distinction that decides the report is reachability, not existence: an administrative share answered from a host inside the assessed boundary is expected, whereas the same share answered from the public internet, or a share that is not one of the default administrative shares (a custom data share, a webroot such as \\inetpub\\wwwroot, or a share an operator created during deployment), means somebody chose to expose it. So this rule rejects the share-presence observation and asks for the boundary or the non-default name before anything is filed.

*Disproof:* The same share is reachable from a host outside the assessed scope boundary (for example the public internet or a partner network), or the share name is not one of the Windows default administrative shares - a custom data share, an IIS webroot such as \inetpub\wwwroot, or a share created by an operator during deployment - which means somebody chose to expose it.

**SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.**

Two shapes get flagged wrongly. First, netsh interface portproxy is a supported Windows redirection facility: a listen port on one interface forwarding to a different address and port, in the observed case a web port forwarded to 445. That is a documented administrative feature and it produces exactly the traffic shape an assessor reads as an SMB pivot. Second, enumeration and exploitation toolkits deliberately live off the land by abusing built-in AD protocols such as SMB, WMI and WinRM, so an SMB session from a management workstation is often the toolkit doing its job rather than an intruder. Before calling either case lateral movement, establish who configured the redirection, from what management context it was created, and whether the SMB peer is in the tool's documented target list.

*Disproof:* If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.

**SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.**

Discard when a scan reported Message signing enabled but not required and nothing was relayed: the BloodHound edge only covers victims with admin access to an unsigned target, and Rapid7 recorded an engagement where signing being not required could not be leveraged at all. It survives when a coerced authentication was actually relayed and authenticated on the second host.

*Disproof:* Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.

**When the target enforces SMB signing the relay stops at authentication, so a signed-session failure is not a broken-signing finding.**

Discard when the tester reported that authentication succeeded but no session could be used: without the shared session key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default. It survives only when the attacker recovered the session key or the target did not require signing.

*Disproof:* Would be wrong where CVE-2019-1019 style session-key retrieval was possible, since then signing provides no protection against relay.
**Hypothesis:** SMB-based lateral movement: unexpected SMB sessions from a host that was not an admin workstation
- Invalidated by: the portproxy entry was a sanctioned administrative redirect with a documented owner, and the SMB peer was that application's backend; the toolkit was also living off the land by design, using built-in SMB/WMI/WinRM
- **Rejection rule:** an SMB session from a management or tooling host is not lateral movement until the redirection and the protocol abuse are shown to lack a sanctioned administrative owner

## Validation

**A relay finding is bounded by the negotiated signing state, so the validation that separates a real relay path from a non-finding is a differential test of the same request with and without a valid signature, not the mere presence of an SMB listener.**

What the primitive gives you: a candidate relay path. Microsoft's signing documentation states that Windows and Windows Server can require outbound signing only, inbound signing only, both, or neither, and that signature mismatches alert users to possible foul play, helping protect deployments against relay and spoofing attacks. Tenable's force-authentication writeup supplies the other half: the credential the first service leaked is only exploitable where it can be replayed, which is precisely what signing state determines. The precondition the next link needs is therefore a specific, measured combination of outbound and inbound policy on the two hosts in the path. Observation that proves the segment: a session with a correct signature succeeds and the same session with an invalid or absent signature is rejected, confirming signing is enforced; the inverse result confirms the path is live.

*Disproof:* If the server accepts unsigned or wrongly-signed SMB sessions on the relevant share, the differential shows no rejection and the relay ceiling is not established by configuration alone; conversely if the server enforces signing on both ends, the relay link is closed and the finding does not hold regardless of listener exposure.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1021/002/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
  - <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing>
- **mollysec.com** (writeup)
  - <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1002.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
