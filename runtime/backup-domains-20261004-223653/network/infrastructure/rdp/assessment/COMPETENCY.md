# Methodology — RDP Abuse

> Derived from 17 verified items. Regenerate with `python -m wks.methodgen --class rdp --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** RDP authenticates the session and, without network level authentication, authenticates the client to the server as well, so reachable RDP is reachable access.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**RDP lateral movement needs only two published facts: a credential for an account that can log in, and an enabled service that accepts those accounts, and neither requires an exploit.**

MITRE's T1021.001 separates the credential problem from the reachability problem and states that adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials, adding that adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Microsoft confirms what the service grants once connected: it allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. The operational consequence is that a password-spray success and an open 3389 compose without any vulnerability, so the hunting question is never whether RDP is exploitable but whether a credential obtained anywhere in the environment is also valid for a host where the service is on. Enumerate credential material by breadth of reuse, and enumerate RDP listeners by scope, then intersect the two sets rather than testing either in isolation.

- *Disproof:* The service is not enabled on the target, or every account with a known credential is denied an interactive logon, through Network Level Authentication, local security policy restrictions, or a jump host that holds the only route to the listener.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

**An attacker who already holds sufficient privileges on a Windows host uses an interactive RDP session, not a file share, as the transport for moving laterally inside the internal network segment.**

The precondition for RDP-based lateral movement is an interactive remote session to a host reachable inside the segment, opened by a normal interactive operator account rather than a service account. Enumerate which accounts hold interactive logon rights to which hosts, then treat any RDP session not attributable to a named administrator workstation as the pivot point rather than the destination. For each RDP session seen on a segment, resolve the source host, the account, and the source address, and ask whether that source host was itself reached interactively earlier in the same window.

- *Disproof:* Proof the claim wrong would be an environment in which lateral movement is routinely performed over SMB, WMI, or scheduled-task transports while RDP sessions on the same hosts are purely interactive admin work with no follow-on execution on the destination; or telemetry showing the RDP sessions in question carried no interactive input, no clipboard redirection and no dynamic channel activity.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.**

Split RDP detections on the destination's role. A session to a workstation is routine; a session to a domain controller lands on a host whose credentials and replication rights are worth taking, so route those first and require a named-operator justification for each. Concretely, resolve every RDP session's destination against the domain controller inventory, pull the RdpCoreTS channel inventory for the ones that match, and check whether the channel set is standard or carries a bulk-transfer channel. Interactive administrative sessions to domain controllers are common enough that the signal is only meaningful when paired with channel and process evidence.

- *Disproof:* Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

**An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.**

Two network-level signals separate an ordinary remote session from a re-routed one: a session bound to a port other than the sanctioned one for that host, and a session whose peer address sits outside the estate's known administrative ranges. Both are cheap to compute from connection telemetry and both are host-independent, so they work even when no endpoint logs are available. Score them together rather than alone -- an off-list port to an internal admin range is usually a misconfiguration, an off-list port to an external address is the case that matters. Confirm by pulling the session's authentication record and asking whether the account was expected at that host at that hour.

- *Disproof:* Proof the claim wrong would be an estate in which the authorized-port inventory is stale -- showing the off-list port is in fact the sanctioned one for that host, or that the external address is a known vendor or bastion egress that policy permits; or telemetry where the flagged session is a health-check or monitoring probe rather than an interactive logon.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.**

rdp2tcp is a publicly available tool that carries TCP over an established RDP connection: a server component runs on the target, a client runs on the attacker side, and the forwarded stream is wrapped in RDP dynamic virtual channels opened after the session is authenticated. Because the payload rides inside a channel of a legitimate RDP connection, per-port firewall rules and port-based detection never see the forwarded service -- there is no new listening port and no new protocol on the wire. Hunt on the channel layer: enumerate the dynamic channel names on each RDP session and treat any channel set beyond the standard RemoteFX set as candidate tunnelling, then confirm by the channel's volume, duration and peer.

- *Disproof:* Proof the claim wrong would be a network where RDP dynamic virtual channels are stripped or negotiated off by policy (an rdpserver channel policy, or a gateway that permits only a fixed channel allow-list), so the client component cannot open a channel and the forward fails; or evidence that the forwarded TCP session completes over a separate, independently authenticated transport rather than inside the RDP connection.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

**Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.**

The RemoteFX module extends the RDP protocol with named virtual channels -- XPSRD, cliprdr, Microsoft::Windows::RDS::DisplayControl and others -- and each of those channels is opened and closed through the same code path, so the RdpCoreTS/Operational log records the channel name for every one of them. That log is the ground truth for what a given RDP session actually did: clipboard redirection, display control, and any additional channel are all distinguishable there. A session carrying only the standard channel set is an ordinary interactive desktop; a session whose channel inventory is broader, or whose channel names fall outside the standard set, is where session hijacking, clipboard-channel abuse, or a data channel surfaces.

- *Disproof:* Proof the claim wrong would be a host where the RdpCoreTS/Operational channel is disabled or its contents cleared before collection, so that neither 132 nor 148 events exist for a session that demonstrably opened channels; or a build in which channel open and close are logged at different event IDs or in a different log entirely.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/advanced-event-log-analysis); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

**RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.**

Microsoft's architecture description is the load-bearing fact: RDP is a multiple-channel capable protocol that allows for separate virtual channels for carrying device communication and presentation data from the server, as well as encrypted client mouse and keyboard data, and it provides an extensible base and supports up to 64,000 separate channels for data transmission. The same page lists virtual channels as a product feature, stating that by using RDP virtual channel architecture existing applications can be augmented and new applications can be developed to add features that require communications between the client device and an application running in a remote desktop session. Why this matters for hunting: the authorisation decision happens at the session, and once it succeeds the attacker inherits whatever channels the server and client have negotiated, including ones added by a remote-control, clipboard-redirection or file-transfer product rather than by Windows itself. A host that looks like a plain RDP endpoint on the wire may be running a set of channel plugins that changes the reachable functionality substantially.

- *Disproof:* The target runs no virtual channel plugin beyond the Microsoft default set, and the client and server negotiate only the standard channels, so the session surface is the base display and input path with no added command channel.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

**An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.**

In practice on HTB this shows up as: |`rexec`|`rexecd`|512|TCP|Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
|`rlogin`|`rlogind`|513|TCP|Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
##### Windows Remote Management (**[RDP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp)** TCP 3389 - **[WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm)** TCP 5985, 5986, ¿47001?)
|**Command**|**Description**|
|-|-|

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/04. Footprinting.md (1810 words, classified network).

- *Disproof:* Refuted when no credential authenticates and Network Level Authentication cannot be bypassed, so no interactive session is obtained.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md)

**Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.**

Microsoft's RDP feature list names the redirection primitives explicitly. Clipboard mapping: users can delete, copy, and paste text and graphics between applications running on the local computer and those running in a remote desktop session, and between sessions. Sound, drive, port, and network printer redirection: sounds that occur on the remote computer can be heard on the client computer running the RDC client, and local client drives will be visible to the remote desktop session. The security consequence is that the RDP session is not only a control channel; it is a synchronisation channel that moves data in both directions, so post-compromise collection does not require a separate exfiltration agent and can look like ordinary administrator clipboard use in the logs. That is why a finding that only reads as a reachable RDP service understates the exposure: hunt the redirection posture on the host, since enabling drive and clipboard redirection on a server holding sensitive data converts any interactive session into an egress path.

- *Disproof:* The target does not implement RDP, or the session is configured with clipboard, drive, port and printer redirection disabled or restricted by group policy, so no client-to-server or server-to-client data path exists beyond the rendered display and injected input.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

**When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.**

The channel name is attacker-controlled when a tunnel tool is in use, so the standard channel set gives way to either the tool's own name or a random alphanumeric channel chosen per engagement. That makes channel naming, not channel count, the sharpest discriminator available to a defender: build an inventory of every channel name observed on the estate, and flag any name that is neither in the RemoteFX standard set nor explained by a sanctioned remote support or graphics product. A non-standard XRDP or third-party RDP stack is the benign version of the same signal, so treat a first sighting as a question and escalate only when the channel also carries bulk bidirectional traffic.

- *Disproof:* Proof the claim wrong would be a session where non-standard channel names appear with no bulk transfer on them -- a graphics or printer redirection product generating its own channel name -- which falsifies channel name alone as a finding; or a build that does not place the negotiated channel name in the 132 and 148 event fields at all, leaving no name to inspect.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

**Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.**

The forwarding is deliberately built from stock Windows functionality so that no new listening service appears: a scheduled task on the target runs a netsh interface portproxy add v4tov4 entry, or a proxy component relays sockets for the operator. The RDP session is the durable anchor -- as long as it lives the forward lives, and the forward's destination is a segment-internal address that was never exposed. Hunt the anchor rather than the forward: enumerate RDP sessions and, for each one, check the target host for portproxy rules and proxy processes whose creation time falls inside the session window.

- *Disproof:* Proof the claim wrong would be showing that the portproxy rule or proxy process on the target predates the RDP session, or was created by a change-management record naming an operator rather than the session account; or evidence that the forwarding runs inside the RDP channel rather than as a separate Windows listener, which would make a portproxy hunt inapplicable to that case.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.**

The discriminating test: for each RDP session to a DC, establish from directory data whether the account was actually entitled to log on there, and compare that entitlement against the session's actual source and time. If the account holds no interactive logon right on that controller, the session is an access-control bypass rather than a misuse of granted rights -- a materially different finding. If it does hold the right, the finding collapses into the expected-administrator false positive and should be closed there. Enumerating that rights data is the step that separates the two, and it is the step most often skipped.

- *Disproof:* Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An RDP session opened by a named administrator from their own workstation to a host inside the declared infrastructure is the expected pattern and must not be reported on session volume or timing alone.**

The lookalike is the ordinary case: an administrator reconnects to the same workstation-hosted hosts repeatedly, including outside business hours, and a rule tuned to large remote-session volume or unusual hours will fire on all of it. The discriminator is whether the session's variables were declared as part of the environment -- the authorized admin ranges, the sanctioned host list and the time windows are inputs to the rule, not facts discovered by it. Before escalating a remote-session anomaly, resolve the source to a named operator and check that the pair (operator, destination) appears in the declared infrastructure; only sessions outside that declaration are candidates.

- *Disproof:* Proof the rule wrong would be a case where a session is fully inside the declared infrastructure -- named operator, sanctioned destination, declared source range -- and is still malicious, for example because the operator's workstation was itself compromised earlier in the engagement; that would mean infrastructure baselining alone cannot carry this class and every session needs per-session channel and process review.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

**A successful RDP logon with a valid account is an authentication event, not proof of exploitation, and is only a finding when the account or the path to the host was not authorised to use it.**

MITRE's technique entry begins from legitimate credential use rather than from a flaw: adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol, and may then perform actions as the logged-on user. The entry is scoped throughout to the case where the service is enabled and allows access to accounts with known credentials, which is a statement about authorisation scope, not about compromise. So the presence of a 4624 logon type 10 for RDP is the expected outcome of an administrator doing their job, and reporting every one produces a corpus of findings that cannot be actioned. What distinguishes a reportable case is a scope violation, not the logon: an account used interactively that policy restricts to non-interactive use, a user reaching a host outside their administrative scope, or a service or user account used for a human session. State the authorisation rule that was crossed, because the disproof is a documented entitlement for that specific principal on that specific host.

- *Disproof:* The account is documented as entitled to an interactive logon on that host, or an approved jump host or management path, and the logon is type 10 for a principal whose policy permits it.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

**A reconnect to a disconnected, not-logged-off RDP session is the documented product behaviour, so the same account and host appearing twice is not by itself evidence of a second interactive session.**

Microsoft's feature list describes roaming disconnect as a capability: a user can manually disconnect from a remote desktop session without logging off, the user is automatically reconnected to their disconnected session when he or she logs back onto the system, either from the same device or a different device, and when a user's session is unexpectedly terminated by a network or client failure the user is disconnected but not logged off. That gives a benign explanation for two logon events for one account against one host that are separated by a gap, and for the second event arriving from a different source address. Triage rule: before calling repeated interactive logons lateral movement, check whether the sessions share a session id or reconnect marker, and whether the earlier session was disconnected rather than logged off. What would make it a real finding is a reconnect whose account, privilege level, or client address differs from the original session without a matching disconnect, since the product reconnects the same principal rather than substituting one.

- *Disproof:* The two events are distinct interactive sessions with different session identifiers and neither is a reconnect of the other, and the earlier session was logged off rather than left disconnected.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A credential valid for RDP plus the default clipboard and drive redirection converts a single interactive logon into bidirectional data movement off the host, without a second tool being deployed.**

Two published facts compose, and the second is what makes the first more than a login. First, the access condition is entirely mundane: adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials, and adversaries will likely use Credential Access techniques to acquire credentials to use with RDP, after which the adversary may then perform actions as the logged-on user. Second, the session carries data in both directions by design, because users can delete, copy, and paste text and graphics between applications running on the local computer and those running in a remote desktop session, and between sessions, with local client drives visible to the remote desktop session under the drive, port, sound and printer redirection feature. The chain therefore needs no implant: the attacker authenticates, reads whatever the logged-on user can read, and copies it out through a channel the protocol provides. The operational consequence is that a hunting rule which only alerts on RDP logons will miss the collection that follows, and a rule which only alerts on large outbound transfers will miss a collection that is measured in clipboard-sized chunks over an interactive session.

- *Disproof:* The session was established with clipboard and drive redirection disabled or restricted by group policy, or the logged-on principal's data is not reachable from the session, so no data crosses the boundary in either direction.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
