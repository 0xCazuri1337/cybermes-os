# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 6 (supported 6), FP rules 3, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 6 (supported 6), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- smb@current
+++ smb@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-732 · OWASP —
 > evidence: 6 items, 6 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.
 
```

## 2026-10-02 10:46 — 23 diff lines
- items: 6 (supported 6), FP rules 4, chains 0, state researching
- still missing: items, chain

```diff
--- smb@current
+++ smb@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-732 · OWASP —
-> evidence: 6 items, 6 supported, 3 FP rules, 0 chains
+> evidence: 6 items, 6 supported, 4 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.
@@ -48,5 +48,11 @@
   - **Disproof:** If SMB signing is mandatory on the first connection, or the target refuses outbound SMB to untrusted peers, or channel binding pins the second service to a TLS channel the attacker does not hold, no NTLM response is emitted or accepted and the relay link has nothing to work with.
   - Sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening> · <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>
 
+## Rejected before you report
+
+- **SMB-based lateral movement: unexpected SMB sessions from a host that was not an admin workstation**
+  - Killed by: the portproxy entry was a sanctioned administrative redirect with a documented owner, and the SMB peer was that application's backend; the toolkit was also living off the land by design, using built-in SMB/WMI/WinRM
+  - Rule: an SMB session from a management or tooling host is not lateral movement until the redirection and the protocol abuse are shown to lack a sanctioned administrative owner
+
 ---
 Full class document: `classes/smb.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
```

## 2026-10-02 10:50 — 21 diff lines
- items: 7 (supported 7), FP rules 5, chains 0, state researching
- still missing: items, chain

```diff
--- smb@current
+++ smb@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-732 · OWASP —
-> evidence: 6 items, 6 supported, 4 FP rules, 0 chains
+> evidence: 7 items, 7 supported, 5 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.
@@ -35,6 +35,9 @@
 - Hidden administrative shares (C$, ADMIN$, IPC$) answering on tcp/445 inside the corporate network are the DEFAULT Windows configuration, not an exposed-share vulnerability; do not file their existence as a finding unless the share is reachable from outside the assessed scope boundary or is created outside the default set (a custom share, a webroot share, or a share added by an operator).
   - **Disproof:** The same share is reachable from a host outside the assessed scope boundary (for example the public internet or a partner network), or the share name is not one of the Windows default administrative shares - a custom data share, an IIS webroot such as \inetpub\wwwroot, or a share created by an operator during deployment - which means somebody chose to expose it.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
+- SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.
+  - **Disproof:** If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.
   - **Disproof:** Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.
   - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/>
```

## 2026-10-02 12:21 — 24 diff lines
- items: 7 (supported 7), FP rules 5, chains 1, state researching
- still missing: items

```diff
--- smb@current
+++ smb@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-732 · OWASP —
-> evidence: 7 items, 7 supported, 5 FP rules, 0 chains
-> maturity: **researching** — missing: items, chain
+> evidence: 7 items, 7 supported, 5 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.
 
@@ -57,5 +57,10 @@
   - Killed by: the portproxy entry was a sanctioned administrative redirect with a documented owner, and the SMB peer was that application's backend; the toolkit was also living off the land by design, using built-in SMB/WMI/WinRM
   - Rule: an SMB session from a management or tooling host is not lateral movement until the redirection and the protocol abuse are shown to lack a sanctioned administrative owner
 
+## Chains to
+
+- `exposed_services` (2 shared chain(s))
+- `lateral_movement` (1 shared chain(s))
+
 ---
 Full class document: `classes/smb.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 7), FP rules 5, chains 1, state researching
- still missing: items

```diff
--- smb@current
+++ smb@new
@@ -63,4 +63,4 @@
 - `lateral_movement` (1 shared chain(s))
 
 ---
-Full class document: `classes/smb.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
+Full class document: `skills/Network + AD/smb/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
```
