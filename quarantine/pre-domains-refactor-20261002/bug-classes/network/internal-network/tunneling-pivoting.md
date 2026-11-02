# Tunneling and Pivoting

## Definition

A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["tunneling", "tunnelling", "pivoting", "socks", "socks proxy", "port forwarding", "proxy", "chisel", "reverse tunnel"]

Canonical home for `tunneling_pivoting`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Continued operator access carried over a legitimate service with no new listening port open is an early observable for tunnelling that no new-port rule will ever fire on.**

A tunnelling operator who wants to stay invisible does not open a port: they encapsulate traffic inside something already allowed so it looks like a benign stream. Observed shapes include Microsoft dev tunnels publishing a local service to a *.devtunnels.ms name, TCP-over-RDP tunnels riding an existing RDP session, and netsh portproxy redirecting a web port to an SMB port. The early observable is therefore behavioural, not port-based: a host maintaining an outbound session to a tunnelling service provider domain, or an inbound web port whose destination is a protocol that does not belong on that port. Port-diff alerting is structurally blind to this because no new port is ever opened.

*Disproof:* If the remote-access exposure is attributable to an approved corporate tunnel service whose domain is on the sanctioned allowlist and whose client was deployed by the platform team, then the session is sanctioned remote access and the tunnelling hypothesis is invalidated.

## Exploitation

**A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.**

Proxies and port forwarding tools are the mechanism; the security consequence is that the enforcement point moves. Where a policy denies a path, an attacker with two footholds and a permitted connection between them can carry the denied traffic as a payload of the permitted one. RFC 4459 makes the same point from the networking side: tunnels are commonly run as multiple layers of encapsulation with a distinct inner and outer path, and the tunnel endpoints may be the same or different hosts. For hunting, the useful observation is at the endpoint — a host that both accepts inbound connections from one segment and originates them to another is the structural precondition, and legitimate tools like remote proxy utilities are indistinguishable from adversary ones by name. Detection therefore looks for the traffic pattern (an established session carrying an unexpected protocol on a permitted port) rather than for the tool.

*Disproof:* If egress from the compromised segment is filtered such that no permitted-protocol channel to an attacker-controlled or third host can carry an inner session, and no dual-homed host bridges the segments, then the tunnel cannot reintroduce the forbidden reachability.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A port forward or tunnel bound to the loopback interface is not a pivot channel and cannot be reached by the attacker.**

Discard when the only evidence is a listener on 127.0.0.1: the forwarding documentation notes that ports opened only on the loopback interface need GatewayPorts before anything external can reach them, so the tunnel proves no external ingress. It survives when the listening socket was bound to a routable interface and accepted a connection from outside the assessment network.

*Disproof:* Would be wrong where an SSH client-side forward plus a local relay on the tester box chains the loopback listener into an externally reachable proxy.

**An SSH or SOCKS tunnel inside the estate is not attacker ingress unless traffic entered from an address the client does not control.**

Discard when the tunnel was observed entirely between hosts inside the scoped network: the intrusion report shows the actor's SSH tunnel was built to present RDP access from a public IP address they owned, which is what distinguishes ingress from internal administration. It survives when the far end of the tunnel was an external or unowned address.

*Disproof:* Would be wrong when the client's own sanctioned jump host relays to the assessment scope, in which case an external-looking leg may still be in-house.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1090/>
- **hackertarget.com** (blog)
  - <https://hackertarget.com/ssh-examples-tunnels/>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/>
  - <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4459.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
