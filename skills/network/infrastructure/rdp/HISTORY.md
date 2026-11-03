# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 15 (supported 15), FP rules 3, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 15 (supported 15), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -79,4 +79,4 @@
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ---
-Full class document: `domains/network/infrastructure/rdp/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
+Full class document: `domains/network/infrastructure/rdp/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
```

## 2026-10-02 19:37 — 40 diff lines
- items: 18 (supported 17), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 15 items, 15 supported, 3 FP rules, 1 chains
+> evidence: 18 items, 17 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
@@ -32,6 +32,9 @@
 
 ## Recon signals (where to look)
 
+- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.
+  - **Disproof:** Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.
   - **Disproof:** Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
   - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
@@ -60,6 +63,18 @@
   - **Disproof:** The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
+## Tests
+
+- To decide this case, observe: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off. What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the produ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+
+## Validation bar (how to prove it)
+
+- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.
+  - **Disproof:** Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+
 ## False-positive rules (when to reject it)
 
 - An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.
```

## 2026-10-03 01:46 — 76 diff lines
- items: 20 (supported 17), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 18 items, 17 supported, 3 FP rules, 1 chains
+> evidence: 20 items, 17 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
@@ -20,9 +20,9 @@
 
 ## Prerequisites (do not start without these)
 
-- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.
+- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change. _(unverified)_
   - **Disproof:** Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.
   - **Disproof:** Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
@@ -37,10 +37,13 @@
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.
   - **Disproof:** Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
+- An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.
+  - **Disproof:** Refuted when no credential authenticates and Network Level Authentication cannot be bypassed, so no interactive session is obtained.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
 - When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.
   - **Disproof:** Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
@@ -50,12 +53,12 @@
 - Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.
   - **Disproof:** Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.
+- RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host. _(unverified)_
   - **Disproof:** If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/>
 - Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.
   - **Disproof:** Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+  - Sources: <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.
   - **Disproof:** Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
   - Sources: <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
@@ -65,7 +68,7 @@
 
 ## Tests
 
-- To decide this case, observe: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off. What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the produ _(unverified)_
+- To decide this case, observe: Triage rule: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
@@ -87,6 +90,12 @@
   - **Disproof:** The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
+## Evidence requirements
+
+- A convincing observation for this class is: What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+
 ## Chaining opportunities
 
 - A credential valid for RDP plus the default clipboard and drive redirection converts a single interactive logon into bidirectional data movement off the host, without a second tool being deployed.
```

## 2026-10-04 00:43 — 145 diff lines
- items: 20 (supported 17), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -20,87 +20,102 @@
 
 ## Prerequisites (do not start without these)
 
-- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change. _(unverified)_
+- An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.
   - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.
-  - **Disproof:** Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.
+- RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.  _(merged 1 duplicate row(s))_
   - **Disproof:** The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## Recon signals (where to look)
 
-- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.
+- An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.
-  - **Disproof:** Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
-- An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.
+- An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when no credential authenticates and Network Level Authentication cannot be bypassed, so no interactive session is obtained.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
-- When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.
+- Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.
+  - Sources: <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+- Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
+  - Sources: <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+- RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/>
+- When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.
-  - **Disproof:** The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
-- Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.
-  - **Disproof:** Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host. _(unverified)_
-  - **Disproof:** If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/>
-- Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.
-  - **Disproof:** Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.
-  - Sources: <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.
-  - **Disproof:** Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
-  - Sources: <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.
-  - **Disproof:** The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## Tests
 
-- To decide this case, observe: Triage rule: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off. _(unverified)_
+- To decide this case, observe: Triage rule: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## Validation bar (how to prove it)
 
-- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.
+- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## False-positive rules (when to reject it)
 
-- An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.
+- A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+- A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The account is documented as entitled to an interactive logon on that host, or an approved jump host or management path, and the logon is type 10 for a principal whose policy permits it.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+- An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the rule wrong would be a case where a session is fully inside the declared infrastructure -- named operator, sanctioned destination, declared source range -- and is still malicious, for example because the operator's workstation was itself compromised earlier in the engagement; that would mean infrastructure baselining alone cannot carry this class and every session needs per-session channel and process review.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.
-  - **Disproof:** The account is documented as entitled to an interactive logon on that host, or an approved jump host or management path, and the logon is type 10 for a principal whose policy permits it.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
-- A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.
-  - **Disproof:** The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.
+- A convincing observation for this class is: What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
... (truncated)
```

## 2026-10-04 00:50 — 14 diff lines
- items: 20 (supported 17), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -105,10 +105,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Check NLA and credential requirements, then test for the known pre-auth weaknesses of the exact protocol build.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 20 (supported 17), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -116,6 +116,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/rdp/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-28 14:45 — 23 diff lines
- items: 20 (supported 18), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 20 items, 17 supported, 3 FP rules, 1 chains
+> evidence: 20 items, 18 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
@@ -59,9 +59,9 @@
 - RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.  _(merged 1 duplicate row(s))_
   - **Disproof:** The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
-- RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.  _(merged 1 duplicate row(s))_ _(unverified)_
+- RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
-  - Sources: <https://attack.mitre.org/techniques/T1021/001/>
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 - When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
```

## 2026-10-28 17:55 — 23 diff lines
- items: 20 (supported 19), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 20 items, 18 supported, 3 FP rules, 1 chains
+> evidence: 20 items, 19 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
@@ -23,9 +23,9 @@
 - An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.  _(merged 1 duplicate row(s))_ _(unverified)_
+- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.
-  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+  - Sources: <https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.  _(merged 1 duplicate row(s))_
   - **Disproof:** The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
```

## 2026-10-31 06:41 — 74 diff lines
- items: 20 (supported 11), FP rules 2, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 20 items, 19 supported, 3 FP rules, 1 chains
+> evidence: 20 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
@@ -26,16 +26,16 @@
 - Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.
   - Sources: <https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.  _(merged 1 duplicate row(s))_
+- RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## Recon signals (where to look)
 
-- An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.  _(merged 1 duplicate row(s))_
+- An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.  _(merged 1 duplicate row(s))_
+- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
@@ -44,7 +44,7 @@
 - An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when no credential authenticates and Network Level Authentication cannot be bypassed, so no interactive session is obtained.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
-- Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.  _(merged 1 duplicate row(s))_
+- Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.
   - Sources: <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.  _(merged 1 duplicate row(s))_
@@ -62,7 +62,7 @@
 - RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
-- When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.  _(merged 1 duplicate row(s))_
+- When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
@@ -74,13 +74,13 @@
 
 ## Validation bar (how to prove it)
 
-- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.  _(merged 1 duplicate row(s))_
+- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## False-positive rules (when to reject it)
 
-- A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.  _(merged 1 duplicate row(s))_
+- A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 - A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.  _(merged 1 duplicate row(s))_
@@ -92,7 +92,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 20 (supported 11), FP rules 2, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -115,7 +115,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/infrastructure/rdp/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
+Full class document: `skills/network/infrastructure/rdp/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 20 (supported 11), FP rules 2, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -5,7 +5,8 @@
 
 # RDP Abuse — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
