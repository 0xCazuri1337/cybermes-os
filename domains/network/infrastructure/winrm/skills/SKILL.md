---
name: winrm-hunting
description: Use when hunting WinRM and PowerShell Remoting in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# WinRM and PowerShell Remoting — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 12 items, 6 supported, 2 FP rules, 1 chains
> maturity: **mature**

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**Also called:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint


## Prerequisites (do not start without these)

- A valid domain credential is not sufficient for WinRM remote execution; by default the principal must be a member of the target's Administrators group, and a local administrator credential is only useful where the same account exists on the target.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The WinRM access finding fails when the credential authenticates but the principal is not in the target's Administrators group, or when the local administrator account does not exist on the destination with the same password.
  - Sources: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>

## Techniques (what to change)

- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.
  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- Post exploitation commands can be executed on the host that has been compromised through the WinRM service.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Tests

- An open TCP 5985 or 5986 listener is not a WinRM finding; proof requires a WSMan session that executes a command as the authenticated user and returns target-specific output.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The WinRM finding fails when the client only opened TCP 5985/5986 or received a protocol banner, and no authenticated WSMan session executed a command on the target.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>

## False-positive rules (when to reject it)

- An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Evidence requirements

- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>

## Defence bypasses

- A local administrator credential from the source host can be reused for WinRM only when the same local account and password exist on the target; a domain credential is not required, but unique local administrator passwords break the hop.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The reuse finding fails when the destination has a different local administrator password, when the account does not exist on the destination, or when the authentication succeeds only with a domain credential rather than the reused local account.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>


## Hunt procedure

1. Test whether plain HTTP is accepted and whether authentication can be negotiated without credentials.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
