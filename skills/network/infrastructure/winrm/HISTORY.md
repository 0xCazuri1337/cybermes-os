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

## 2026-10-04 00:43 — 90 diff lines
- items: 14 (supported 5), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -20,54 +20,54 @@
 
 ## Techniques (what to change)
 
-- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. _(unverified)_
+- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
+  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
+- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
+  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Post exploitation commands can be executed on the host that has been compromised through the WinRM service. _(unverified)_
+- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Post exploitation commands can be executed on the host that has been compromised through the WinRM service. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.
-  - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
-  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
-- WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.
+  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+- WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
+- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.  _(merged 3 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
+  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
 ## False-positive rules (when to reject it)
 
-- WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.
+- An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
+  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+- WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.  _(merged 1 duplicate row(s))_
   - **Disproof:** Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
-  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.
-  - **Disproof:** Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.
+- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 14 (supported 5), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -57,10 +57,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Test whether plain HTTP is accepted and whether authentication can be negotiated without credentials.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 14 (supported 5), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -68,6 +68,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 40 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 14 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.
@@ -23,20 +23,20 @@
 - A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
+- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
+- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
+- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 - WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.  _(merged 3 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
+- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.  _(merged 3 duplicate row(s))_
+  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
 ## False-positive rules (when to reject it)
```

## 2026-10-28 14:39 — 70 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.
@@ -18,26 +18,38 @@
 **Also called:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint
 
 
+## Prerequisites (do not start without these)
+
+- A valid domain credential is not sufficient for WinRM remote execution; by default the principal must be a member of the target's Administrators group, and a local administrator credential is only useful where the same account exists on the target.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The WinRM access finding fails when the credential authenticates but the principal is not in the target's Administrators group, or when the local administrator account does not exist on the destination with the same password.
+  - Sources: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
+
 ## Techniques (what to change)
 
 - A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 2 duplicate row(s))_
+- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 2 duplicate row(s))_
+  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
-- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.  _(merged 2 duplicate row(s))_
+- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 - WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
-- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.  _(merged 3 duplicate row(s))_
+- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
+
+## Tests
+
+- An open TCP 5985 or 5986 listener is not a WinRM finding; proof requires a WSMan session that executes a command as the authenticated user and returns target-specific output.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The WinRM finding fails when the client only opened TCP 5985/5986 or received a protocol banner, and no authenticated WSMan session executed a command on the target.
+  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
 
 ## False-positive rules (when to reject it)
 
@@ -53,6 +65,12 @@
 - A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
+
+## Defence bypasses
+
+- A local administrator credential from the source host can be reused for WinRM only when the same local account and password exist on the target; a domain credential is not required, but unique local administrator passwords break the hop.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The reuse finding fails when the destination has a different local administrator password, when the account does not exist on the destination, or when the authentication succeeds only with a domain credential rather than the reused local account.
+  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
 
 ## Hunt procedure
```

## 2026-10-31 06:41 — 56 diff lines
- items: 12 (supported 6), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.
@@ -20,16 +20,16 @@
 
 ## Prerequisites (do not start without these)
 
-- A valid domain credential is not sufficient for WinRM remote execution; by default the principal must be a member of the target's Administrators group, and a local administrator credential is only useful where the same account exists on the target.  _(merged 1 duplicate row(s))_
+- A valid domain credential is not sufficient for WinRM remote execution; by default the principal must be a member of the target's Administrators group, and a local administrator credential is only useful where the same account exists on the target.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The WinRM access finding fails when the credential authenticates but the principal is not in the target's Administrators group, or when the local administrator account does not exist on the destination with the same password.
   - Sources: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
 
 ## Techniques (what to change)
 
-- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.  _(merged 1 duplicate row(s))_
+- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
-- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 1 duplicate row(s))_
+- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 - In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 1 duplicate row(s))_
@@ -47,7 +47,7 @@
 
 ## Tests
 
-- An open TCP 5985 or 5986 listener is not a WinRM finding; proof requires a WSMan session that executes a command as the authenticated user and returns target-specific output.  _(merged 1 duplicate row(s))_
+- An open TCP 5985 or 5986 listener is not a WinRM finding; proof requires a WSMan session that executes a command as the authenticated user and returns target-specific output.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The WinRM finding fails when the client only opened TCP 5985/5986 or received a protocol banner, and no authenticated WSMan session executed a command on the target.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
 
@@ -62,13 +62,13 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
 
 ## Defence bypasses
 
-- A local administrator credential from the source host can be reused for WinRM only when the same local account and password exist on the target; a domain credential is not required, but unique local administrator passwords break the hop.  _(merged 1 duplicate row(s))_
+- A local administrator credential from the source host can be reused for WinRM only when the same local account and password exist on the target; a domain credential is not required, but unique local administrator passwords break the hop.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The reuse finding fails when the destination has a different local administrator password, when the account does not exist on the destination, or when the authentication succeeds only with a domain credential rather than the reused local account.
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 12 (supported 6), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -85,7 +85,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
+Full class document: `skills/network/infrastructure/winrm/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 12 (supported 6), FP rules 2, chains 1, state mature

```diff
--- winrm@current
+++ winrm@new
@@ -5,7 +5,8 @@
 
 # WinRM and PowerShell Remoting — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
