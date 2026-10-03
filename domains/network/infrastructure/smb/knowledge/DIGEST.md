# SMB/CIFS Abuse

> surface: `net` · CWE: CWE-732 · OWASP: —
> maturity: **mature** — 13 items, 13 supported, 5 FP rules, 1 chains

SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.

**Aliases:** smb, cifs, null session, guest session, smb signing, smb1, named pipe coercion, share enumeration, psexec

## Technique

- **SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.**  
  `high_confidence` · score 0.8615 · disproved by: If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.
  sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://www.rfc-editor.org/rfc/rfc1002.html>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.7755 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
- **For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>

## Validation

- **A relay finding is bounded by the negotiated signing state, so the validation that separates a real relay path from a non-finding is a differential test of the same request with and without a valid signature, not the mere presence of an SMB listener.**  
  `high_confidence` · score 0.8905 · disproved by: If the server accepts unsigned or wrongly-signed SMB sessions on the relevant share, the differential shows no rejection and the relay ceiling is not established by configuration alone; conversely if the server enforces signing on both ends, the relay link is closed and the finding does not hold regardless of listener exposure.
  sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>

## Fp Rule

- **Hidden administrative shares (C$, ADMIN$, IPC$) answering on tcp/445 inside the corporate network are the DEFAULT Windows configuration, not an exposed-share vulnerability; do not file their existence as a finding unless the share is reachable from outside the assessed scope boundary or is created outside the default set (a custom share, a webroot share, or a share added by an operator).**  
  `high_confidence` · score 0.844 · disproved by: The same share is reachable from a host outside the assessed scope boundary (for example the public internet or a partner network), or the share name is not one of the Windows default administrative shares - a custom data share, an IIS webroot such as \inetpub\wwwroot, or a share created by an operator during deployment - which means somebody chose to expose it.
  sources: <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- **SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.
  sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/>
- **When the target enforces SMB signing the relay stops at authentication, so a signed-session failure is not a broken-signing finding.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong where CVE-2019-1019 style session-key retrieval was possible, since then signing provides no protection against relay.
  sources: <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.**  
  `high_confidence` · score 0.808 · disproved by: If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Chain Link

- **A server that initiates an outbound SMB connect to an attacker-chosen host will answer that host's challenge with its own NTLM credentials, so a force-authentication primitive converts an unauthenticated connection into a relayable credential without the attacker ever holding a password.**  
  `high_confidence` · score 0.899 · disproved by: If SMB signing is mandatory on the first connection, or the target refuses outbound SMB to untrusted peers, or channel binding pins the second service to a TLS channel the attacker does not hold, no NTLM response is emitted or accepted and the relay link has nothing to work with.
  sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening> · <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>

## False-positive rules

- **Hypothesis:** SMB-based lateral movement: unexpected SMB sessions from a host that was not an admin workstation
  - **Invalidated by:** the portproxy entry was a sanctioned administrative redirect with a documented owner, and the SMB peer was that application's backend; the toolkit was also living off the land by design, using built-in SMB/WMI/WinRM
  - **Rule:** an SMB session from a management or tooling host is not lateral movement until the redirection and the protocol abuse are shown to lack a sanctioned administrative owner

## Related classes (via chains)

- `exposed_services` Exposed Remote Services (2 chains)
- `lateral_movement` Lateral Movement (1 chains)
