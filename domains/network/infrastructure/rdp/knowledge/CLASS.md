# RDP Abuse

## Definition

RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["rdp", "remote desktop", "nla", "network level authentication", "session hijacking", "terminal services"]

Canonical home for `rdp`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.**

Dev tunnels are a legitimate Microsoft developer feature for publishing local services. An attacker who reaches a developer workstation or build agent running the tunnel client inherits that capability for free: the local RDP listener is published outbound through the tunnel service, so the endpoint appears on the internet while the host's own firewall still shows 3389 as never exposed. Prerequisite checks for this class are therefore not limited to inbound 3389 scanning -- outbound connections from inside a segment to devtunnels.ms hostnames carrying RDP negotiation, and tunnel client processes running on developer hosts, are the observables that matter.

*Disproof:* Proof the claim wrong would be a dev tunnel deployment in which the published port is not 3389 and no RDP protocol negotiation appears on the tunnel, or evidence that the tunnel client refuses to forward a loopback RDP listener; equally, showing the exposed hostname resolves to a public IP that answers only HTTP falsifies this specific claim about port 3389 publication.

**An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.**

The precondition for RDP-based lateral movement is an interactive remote session to a host reachable inside the segment, opened by a normal interactive operator account rather than a service account. Enumerate which accounts hold interactive logon rights to which hosts, then treat any RDP session not attributable to a named administrator workstation as the pivot point rather than the destination. For each RDP session seen on a segment, resolve the source host, the account, and the source address, and ask whether that source host was itself reached interactively earlier in the same window.

*Disproof:* Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.

**RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.**

MITRE's T1021.001 separates the credential problem from the reachability problem and states that adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials, adding that adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Microsoft confirms what the service grants once connected: it allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. The operational consequence is that a password-spray success and an open 3389 compose without any vulnerability, so the hunting question is never whether RDP is exploitable but whether a credential obtained anywhere in the environment is also valid for a host where the service is on. Enumerate credential material by breadth of reuse, and enumerate RDP listeners by scope, then intersect the two sets rather than testing either in isolation.

*Disproof:* The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.**

Split RDP detections on the destination's role. A session to a workstation is routine; a session to a domain controller lands on a host whose credentials and replication rights are worth taking, so route those first and require a named-operator justification for each. Concretely, resolve every RDP session's destination against the domain controller inventory, pull the RdpCoreTS channel inventory for the ones that match, and check whether the channel set is standard or carries a bulk-transfer channel. Interactive administrative sessions to domain controllers are common enough that the signal is only meaningful when paired with channel and process evidence.

*Disproof:* Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.

**An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.**

Two network-level signals separate an ordinary remote session from a re-routed one: a session bound to a port other than the sanctioned one for that host, and a session whose peer address sits outside the estate's known administrative ranges. Both are cheap to compute from connection telemetry and both are host-independent, so they work even when no endpoint logs are available. Score them together rather than alone -- an off-list port to an internal admin range is usually a misconfiguration, an off-list port to an external address is the case that matters. Confirm by pulling the session's authentication record and asking whether the account was expected at that host at that hour.

*Disproof:* Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.

**A convincing observation for this class is: What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.**

Derived from rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.

## Exploitation

**An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.**

In practice on HTB this shows up as: |`rexec`|`rexecd`|512|TCP|Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
|`rlogin`|`rlogind`|513|TCP|Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
##### Windows Remote Management (**[RDP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp)** TCP 3389 - **[WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm)** TCP 5985, 5986, ¿47001?)
|**Command**|**Description**|
|-|-|

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/04. Footprinting.md (1810 words, classified network).

*Disproof:* Refuted when no credential authenticates and Network Level Authentication cannot be bypassed, so no interactive session is obtained.

**When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.**

The channel name is attacker-controlled when a tunnel tool is in use, so the standard channel set gives way to either the tool's own name or a random alphanumeric channel chosen per engagement. That makes channel naming, not channel count, the sharpest discriminator available to a defender: build an inventory of every channel name observed on the estate, and flag any name that is neither in the RemoteFX standard set nor explained by a sanctioned remote support or graphics product. A non-standard XRDP or third-party RDP stack is the benign version of the same signal, so treat a first sighting as a question and escalate only when the channel also carries bulk bidirectional traffic.

*Disproof:* Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.

**Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.**

Microsoft's RDP feature list names the redirection primitives explicitly. Clipboard mapping: users can delete, copy, and paste text and graphics between applications running on the local computer and those running in a remote desktop session, and between sessions. Sound, drive, port, and network printer redirection: sounds that occur on the remote computer can be heard on the client computer running the RDC client, and local client drives will be visible to the remote desktop session. The security consequence is that the RDP session is not only a control channel; it is a synchronisation channel that moves data in both directions, so post-compromise collection does not require a separate exfiltration agent and can look like ordinary administrator clipboard use in the logs. That is why a finding that only reads as a reachable RDP service understates the exposure: hunt the redirection posture on the host, since enabling drive and clipboard redirection on a server holding sensitive data converts any interactive session into an egress path.

*Disproof:* The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.

**Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.**

The forwarding is deliberately built from stock Windows functionality so that no new listening service appears: a scheduled task on the target runs a netsh interface portproxy add v4tov4 entry, or a proxy component relays sockets for the operator. The RDP session is the durable anchor -- as long as it lives the forward lives, and the forward's destination is a segment-internal address that was never exposed. Hunt the anchor rather than the forward: enumerate RDP sessions and, for each one, check the target host for portproxy rules and proxy processes whose creation time falls inside the session window.

*Disproof:* Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.

**RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.**

RDP is a multi-channel protocol carrying presentation data, device channels and encrypted input events, with the server rendering output into packets and the client turning them back into graphics calls. The hunting consequence is that this is not a metadata service: an RDP listener reachable from an unexpected segment is an interactive session reachable from there. Microsoft documents the protocol as designed to support different network topologies and multiple LAN protocols, which is precisely why the reachability question is a network-topology question rather than a port question. Pair it with the credential question: ATT&CK notes that adversaries expand access over RDP when the service is enabled and permits accounts with known credentials, so an enabled-but-restricted listener and an enabled-and-open listener are different findings. Recorded sessions are also a persistence surface in their own right, which is why RDP shows up outside movement.

*Disproof:* If the RDP listener requires network-level authentication and is firewalled to jump hosts only, so that no unauthorized host can reach the port, then RDP reachability does not imply session reachability.

**Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.**

rdp2tcp is a publicly available tool that carries TCP over an established RDP connection: a server component runs on the target, a client runs on the attacker side, and the forwarded stream is wrapped in RDP dynamic virtual channels opened after the session is authenticated. Because the payload rides inside a channel of a legitimate RDP connection, per-port firewall rules and port-based detection never see the forwarded service -- there is no new listening port and no new protocol on the wire. Hunt on the channel layer: enumerate the dynamic channel names on each RDP session and treat any channel set beyond the standard RemoteFX set as candidate tunnelling, then confirm by the channel's volume, duration and peer.

*Disproof:* Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.

**Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.**

The RemoteFX module extends the RDP protocol with named virtual channels -- XPSRD, cliprdr, Microsoft::Windows::RDS::DisplayControl and others -- and each of those channels is opened and closed through the same code path, so the RdpCoreTS/Operational log records the channel name for every one of them. That log is the ground truth for what a given RDP session actually did: clipboard redirection, display control, and any additional channel are all distinguishable there. A session carrying only the standard channel set is an ordinary interactive desktop; a session whose channel inventory is broader, or whose channel names fall outside the standard set, is where session hijacking, clipboard-channel abuse, or a data channel surfaces.

*Disproof:* Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.

**RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.**

Microsoft's architecture description is the load-bearing fact: RDP is a multiple-channel capable protocol that allows for separate virtual channels for carrying device communication and presentation data from the server, as well as encrypted client mouse and keyboard data, and it provides an extensible base and supports up to 64,000 separate channels for data transmission. The same page lists virtual channels as a product feature, stating that by using RDP virtual channel architecture existing applications can be augmented and new applications can be developed to add features that require communications between the client device and an application running in a remote desktop session. Why this matters for hunting: the authorisation decision happens at the session, and once it succeeds the attacker inherits whatever channels the server and client have negotiated, including ones added by a remote-control, clipboard-redirection or file-transfer product rather than by Windows itself. A host that looks like a plain RDP endpoint on the wire may be running a set of channel plugins that changes the reachable functionality substantially.

*Disproof:* The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `rdp-valid-account-to-clipboard-exfiltration` — Valid-account RDP logon to clipboard and drive data exfiltration (goal: `Use a credential obtained elsewhere in the environment to establish an RDP session and move data off the target through the protocol's own redirection channels, without deploying an exfiltration agent.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.**

The lookalike is the ordinary case: an administrator reconnects to the same workstation-hosted hosts repeatedly, including outside business hours, and a rule tuned to large remote-session volume or unusual hours will fire on all of it. The discriminator is whether the session's variables were declared as part of the environment -- the authorized admin ranges, the sanctioned host list and the time windows are inputs to the rule, not facts discovered by it. Before escalating a remote-session anomaly, resolve the source to a named operator and check that the pair (operator, destination) appears in the declared infrastructure; only sessions outside that declaration are candidates.

*Disproof:* Proof the rule wrong would be a case where a session is fully inside the declared infrastructure -- named operator, sanctioned destination, declared source range -- and is still malicious, for example because the operator's workstation was itself compromised earlier in the engagement; that would mean infrastructure baselining alone cannot carry this class and every session needs per-session channel and process review.

**A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.**

MITRE's technique entry begins from legitimate credential use rather than from a flaw: adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol, and may then perform actions as the logged-on user. The entry is scoped throughout to the case where the service is enabled and allows access to accounts with known credentials, which is a statement about authorisation scope, not about compromise. So the presence of a 4624 logon type 10 for RDP is the expected outcome of an administrator doing their job, and reporting every one produces a corpus of findings that cannot be actioned. What distinguishes a reportable case is a scope violation, not the logon: an account used interactively that policy restricts to non-interactive use, a user reaching a host outside their administrative scope, or a service or user account used for a human session. State the authorisation rule that was crossed, because the disproof is a documented entitlement for that specific principal on that specific host.

*Disproof:* The account is documented as entitled to an interactive logon on that host, or an approved jump host or management path, and the logon is type 10 for a principal whose policy permits it.

**A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.**

Microsoft's feature list describes roaming disconnect as a capability: a user can manually disconnect from a remote desktop session without logging off, the user is automatically reconnected to their disconnected session when he or she logs back onto the system, either from the same device or a different device, and when a user's session is unexpectedly terminated by a network or client failure the user is disconnected but not logged off. That gives a benign explanation for two logon events for one account against one host that are separated by a gap, and for the second event arriving from a different source address. Triage rule: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off. What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.

*Disproof:* The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.

## Validation

**A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.**

The discriminating test: for each RDP session to a DC, establish from directory data whether the account was actually entitled to log on there, and compare that entitlement against the session's actual source and time. If the account holds no interactive logon right on that controller, the session is an access-control bypass rather than a misuse of granted rights -- a materially different finding. If it does hold the right, the finding collapses into the expected-administrator false positive and should be closed there. Enumerating that rights data is the step that separates the two, and it is the step most often skipped.

*Disproof:* Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.

**To decide this case, observe: Triage rule: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off.**

Derived from rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (rdp.fp_rule.reconnect_after_abandoned_session_is_not_lateral_movement) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
  - <https://academy.hackthebox.com/course/preview/active-directory-ldap>
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
  - <https://academy.hackthebox.com/course/preview/advanced-event-log-analysis>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1021/001/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
