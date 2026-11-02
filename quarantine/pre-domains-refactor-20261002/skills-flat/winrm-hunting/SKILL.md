---
name: winrm-hunting
description: Use when hunting WinRM and PowerShell Remoting in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# WinRM and PowerShell Remoting — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 4 items, 3 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, chain

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**Also called:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint


## Techniques (what to change)

- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host. _(unverified)_
  - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
  - Sources: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
- WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.
  - **Disproof:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>

## False-positive rules (when to reject it)

- WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.
  - **Disproof:** Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.
  - **Disproof:** Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

---
Full class document: `skills/Network + AD/winrm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
