<!-- GENERATED from db/wks.db — do not edit -->
# RDP Abuse

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 20 items, 11 supported, 2 FP rules, 1 chains

RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.

**Aliases:** rdp, remote desktop, nla, network level authentication, session hijacking, terminal services

## Prerequisite

- **Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.**  
  `high_confidence` · score 0.8715 · disproved by: Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.
  sources: <https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.**  
  `high_confidence` · score 0.844 · disproved by: Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Technique

- **RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.**  
  `high_confidence` · score 0.85 · disproved by: If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
- **Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.**  
  `high_confidence` · score 0.844 · disproved by: Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
  sources: <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.**  
  `high_confidence` · score 0.8415 · disproved by: The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
- **An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when no credential authenticates and Network Level Authentication cannot be bypassed, so no interactive session is obtained.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- **Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.**  
  `high_confidence` · score 0.814 · disproved by: The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
- **Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.**  
  `high_confidence` · score 0.808 · disproved by: Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Fp Rule

- **An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.**  
  `high_confidence` · score 0.808 · disproved by: Proof the rule wrong would be a case where a session is fully inside the declared infrastructure -- named operator, sanctioned destination, declared source range -- and is still malicious, for example because the operator's workstation was itself compromised earlier in the engagement; that would mean infrastructure baselining alone cannot carry this class and every session needs per-session channel and process review.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.**  
  `high_confidence` · score 0.778 · disproved by: The account is documented as entitled to an interactive logon on that host, or an approved jump host or management path, and the logon is type 10 for a principal whose policy permits it.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>

## Chain Link

- **A credential valid for RDP plus the default clipboard and drive redirection converts a single interactive logon into bidirectional data movement off the host, without a second tool being deployed.**  
  `high_confidence` · score 0.85 · disproved by: The session was established with clipboard and drive redirection disabled or restricted by group policy, or the logged-on principal's data is not reachable from the session, so no data crosses the boundary in either direction.
  sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
