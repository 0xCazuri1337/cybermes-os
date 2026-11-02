# Methodology — Tunneling and Pivoting

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class tunneling_pivoting --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.

**References.** CWE-200

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Continued operator access carried over a legitimate service with no new listening port open is an early observable for tunnelling that no new-port rule will ever fire on.**

A tunnelling operator who wants to stay invisible does not open a port: they encapsulate traffic inside something already allowed so it looks like a benign stream. Observed shapes include Microsoft dev tunnels publishing a local service to a *.devtunnels.ms name, TCP-over-RDP tunnels riding an existing RDP session, and netsh portproxy redirecting a web port to an SMB port. The early observable is therefore behavioural, not port-based: a host maintaining an outbound session to a tunnelling service provider domain, or an inbound web port whose destination is a protocol that does not belong on that port. Port-diff alerting is structurally blind to this because no new port is ever opened.

- *Disproof:* If the remote-access exposure is attributable to an approved corporate tunnel service whose domain is on the sanctioned allowlist and whose client was deployed by the platform team, then the session is sanctioned remote access and the tunnelling hypothesis is invalidated.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.**

Proxies and port forwarding tools are the mechanism; the security consequence is that the enforcement point moves. Where a policy denies a path, an attacker with two footholds and a permitted connection between them can carry the denied traffic as a payload of the permitted one. RFC 4459 makes the same point from the networking side: tunnels are commonly run as multiple layers of encapsulation with a distinct inner and outer path, and the tunnel endpoints may be the same or different hosts. For hunting, the useful observation is at the endpoint — a host that both accepts inbound connections from one segment and originates them to another is the structural precondition, and legitimate tools like remote proxy utilities are indistinguishable from adversary ones by name. Detection therefore looks for the traffic pattern (an established session carrying an unexpected protocol on a permitted port) rather than for the tool.

- *Disproof:* If egress from the compromised segment is filtered such that no permitted-protocol channel to an attacker-controlled or third host can carry an inner session, and no dual-homed host bridges the segments, then the tunnel cannot reintroduce the forbidden reachability.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1090/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4459.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A port forward or tunnel bound to the loopback interface is not a pivot channel and cannot be reached by the attacker.**

Discard when the only evidence is a listener on 127.0.0.1: the forwarding documentation notes that ports opened only on the loopback interface need GatewayPorts before anything external can reach them, so the tunnel proves no external ingress. It survives when the listening socket was bound to a routable interface and accepted a connection from outside the assessment network.

- *Disproof:* Would be wrong where an SSH client-side forward plus a local relay on the tester box chains the loopback listener into an externally reachable proxy.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/); [thehacker.recipes](https://www.thehacker.recipes/infra/pivoting/port-forwarding)

**An SSH or SOCKS tunnel inside the estate is not attacker ingress unless traffic entered from an address the client does not control.**

Discard when the tunnel was observed entirely between hosts inside the scoped network: the intrusion report shows the actor's SSH tunnel was built to present RDP access from a public IP address they owned, which is what distinguishes ingress from internal administration. It survives when the far end of the tunnel was an external or unowned address.

- *Disproof:* Would be wrong when the client's own sanctioned jump host relays to the assessment scope, in which case an external-looking leg may still be in-house.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/); [thehacker.recipes](https://www.thehacker.recipes/infra/pivoting/port-forwarding)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A reverse-tunnel implant on a compromised host turns that host into a generic TCP forwarder reachable from attacker infrastructure, so the next link gets reachability to internal-only management services without a credential, because the packet source is the internal host itself.**

Previous primitive hands over: code execution on an internal host. Microsoft observed a campaign that ultimately deployed a Python-based reverse-tunnel C2 implant that tunnels arbitrary TCP traffic back through an encrypted WebSocket channel to attacker infrastructure, and noted this gives direct access to an organization's internal network through the reverse tunnel. Precondition the NEXT link needs: an internal service whose reachability is the only control, not its authentication, because the tunnelled traffic originates at the internal host. HackerTarget makes the same property explicit for the forward direction: traffic to the remote systems has a source of the remote server, so anything keyed to source address now passes. Observation that proves this segment: a request issued through the tunnel reaches an internal-only port and its response returns with the internal host's addressing, proving the encapsulation reintroduced forbidden reachability.

- *Disproof:* If the internal service authenticates every request regardless of source, or egress filtering blocks the implant's outbound channel, or the tunnel is bound to a fixed destination that excludes the service being attempted, the handoff produces no new reachability and the pivot chain ends at the first host.
- *Evidence:* high_confidence — [hackertarget.com](https://hackertarget.com/ssh-examples-tunnels/); [microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
