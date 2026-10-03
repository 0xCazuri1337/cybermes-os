# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 15 (supported 15), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 15 (supported 15), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -70,4 +70,4 @@
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
 ---
-Full class document: `domains/network/infrastructure/winrm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
+Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
```

## 2026-10-02 19:37 — 59 diff lines
- items: 13 (supported 4), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 15 items, 15 supported, 2 FP rules, 1 chains
+> evidence: 13 items, 4 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.
@@ -20,38 +20,32 @@
 
 ## Techniques (what to change)
 
-- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.
+- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.
+- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.
+- Post exploitation commands can be executed on the host that has been compromised through the WinRM service. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.
+- Post exploitation commands can be executed on the host that has been compromised through the WinRM service. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.
+- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.
+- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.
+- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.
+- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.
+- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Upon exploitation the module will attempt to modify the PowerShell execution policy to all".
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Upon exploitation the module will attempt to modify the PowerShell execution policy to all".
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 - A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.
   - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
```

## 2026-10-03 01:46 — 23 diff lines
- items: 14 (supported 5), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 13 items, 4 supported, 2 FP rules, 1 chains
+> evidence: 14 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.
@@ -63,5 +63,11 @@
   - **Disproof:** Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
+
 ---
 Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
```
