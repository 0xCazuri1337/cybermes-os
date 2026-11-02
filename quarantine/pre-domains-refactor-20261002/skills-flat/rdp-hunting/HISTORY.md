# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 1 (supported 1), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 1 (supported 1), FP rules 0, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- rdp@current
+++ rdp@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 1 items, 1 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
 
```

## 2026-10-02 12:21 — 57 diff lines
- items: 9 (supported 9), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- rdp@current
+++ rdp@new
@@ -10,19 +10,52 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 1 items, 1 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 9 items, 9 supported, 1 FP rules, 0 chains
+> maturity: **researching** — missing: items, fp_rules, chain
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
 
 **Also called:** rdp, remote desktop, nla, network level authentication, session hijacking, terminal services
 
 
+## Prerequisites (do not start without these)
+
+- Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.
+  - **Disproof:** Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.
+  - **Disproof:** Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+
+## Recon signals (where to look)
+
+- An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.
+  - **Disproof:** Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
+  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+
 ## Techniques (what to change)
 
+- When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.
+  - **Disproof:** Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.
+  - **Disproof:** Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.
   - **Disproof:** If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.
   - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+- Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.
+  - **Disproof:** Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.
+  - **Disproof:** Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
+  - Sources: <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+
+## False-positive rules (when to reject it)
+
+- An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.
+  - **Disproof:** Proof the rule wrong would be a case where a session is fully inside the declared infrastructure -- named operator, sanctioned destination, declared source range -- and is still malicious, for example because the operator's workstation was itself compromised earlier in the engagement; that would mean infrastructure baselining alone cannot carry this class and every session needs per-session channel and process review.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ---
 Full class document: `classes/rdp.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
```

## 2026-10-02 13:38 — 62 diff lines
- items: 15 (supported 15), FP rules 3, chains 1, state mature

```diff
--- rdp@current
+++ rdp@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 9 items, 9 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: items, fp_rules, chain
+> evidence: 15 items, 15 supported, 3 FP rules, 1 chains
+> maturity: **mature**
 
 RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.
 
@@ -26,6 +26,9 @@
 - An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.
   - **Disproof:** Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.
+  - **Disproof:** The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## Recon signals (where to look)
 
@@ -38,6 +41,9 @@
 - When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.
   - **Disproof:** Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.
+  - **Disproof:** The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 - Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.
   - **Disproof:** Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
@@ -50,12 +56,27 @@
 - Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.
   - **Disproof:** Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
   - Sources: <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.
+  - **Disproof:** The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ## False-positive rules (when to reject it)
 
 - An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.
   - **Disproof:** Proof the rule wrong would be a case where a session is fully inside the declared infrastructure -- named operator, sanctioned destination, declared source range -- and is still malicious, for example because the operator's workstation was itself compromised earlier in the engagement; that would mean infrastructure baselining alone cannot carry this class and every session needs per-session channel and process review.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+- A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.
+  - **Disproof:** The account is documented as entitled to an interactive logon on that host, or an approved jump host or management path, and the logon is type 10 for a principal whose policy permits it.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+- A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.
+  - **Disproof:** The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+
+## Chaining opportunities
+
+- A credential valid for RDP plus the default clipboard and drive redirection converts a single interactive logon into bidirectional data movement off the host, without a second tool being deployed.
+  - **Disproof:** The session was established with clipboard and drive redirection disabled or restricted by group policy, or the logged-on principal's data is not reachable from the session, so no data crosses the boundary in either direction.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
 
 ---
-Full class document: `classes/rdp.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
+Full class document: `skills/Network + AD/rdp/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id rdp`
```
