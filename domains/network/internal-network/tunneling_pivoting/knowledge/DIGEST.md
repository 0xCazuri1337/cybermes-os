# Tunneling and Pivoting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 12 items, 6 supported, 1 FP rules, 1 chains

A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.

**Aliases:** tunneling, tunnelling, pivoting, socks, socks proxy, port forwarding, proxy, chisel, reverse tunnel

## Signal

- **Continued operator access carried over a legitimate service with no new listening port open is an early observable for tunnelling that no new-port rule will ever fire on.**  
  `under_review` · score 0.844 · disproved by: If the remote-access exposure is attributable to an approved corporate tunnel service whose domain is on the sanctioned allowlist and whose client was deployed by the platform team, then the session is sanctioned remote access and the tunnelling hypothesis is invalidated.
  sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/>

## Technique

- **A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.**  
  `high_confidence` · score 0.853 · disproved by: If egress from the compromised segment is filtered such that no permitted-protocol channel to an attacker-controlled or third host can carry an inner session, and no dual-homed host bridges the segments, then the tunnel cannot reintroduce the forbidden reachability.
  sources: <https://attack.mitre.org/techniques/T1090/> · <https://www.rfc-editor.org/rfc/rfc4459.html>
- **A pivot is established by tunnelling traffic for a second network segment through the already-compromised host, which carries no credentials of its own.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the compromised host cannot open outbound connections to the second segment, or no listener can be bound on the far side, so the tunnel never carries traffic.
  sources: <https://attack.mitre.org/techniques/T1090/> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/04.%20Exploitation/20.%20Pivoting%2C%20Tunneling%20%26%20Port%20Forwarding/Pivoting%2C%20Tunneling%20%26%20Port%20Forwarding.md>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `under_review` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- **Using one compromised machine to access another is called pivoting and allows us to access networks and resources that are not directly accessible to us through the compromised host.**  
  `high_confidence` · score 0.788 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Using one compromised machine to access another is called pivoting and allows us”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- **Tunneling is a technique that allows us to encapsulate traffic within another protocol so that it looks like a benign traffic stream.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Tunneling is a technique that allows us to encapsulate traffic within another pr”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **This is known as pivoting and enables lateral movement through the network.**  
  `under_review` · score 0.762 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This is known as pivoting and enables lateral movement through the network.”) does not occur under a test that isolates that control.
  sources: <https://attack.mitre.org/techniques/T1090/> · <https://hackertarget.com/ssh-examples-tunnels/>

## Test

- **To decide this case, observe: Discard when the tunnel was observed entirely between hosts inside the scoped network: the intrusion report shows the actor's SSH tunnel was built to present RDP access from a public IP address they owned, which is what distinguishes ingress from internal administration.**  
  `under_review` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (tunneling_pivoting.fprule.tunnel_without_ingress) states the full boundary.
  sources: <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>
- **A pivot is proven only when a host that was unreachable from the assessment origin becomes reachable through a compromised intermediary; an open proxy or tunnel endpoint alone does not demonstrate a new network path.**  
  `under_review` · score 0.863 · disproved by: The pivot finding fails when the destination answers identically from the assessment origin, when the tunnel only exposes a loopback or same-host service, or when no service beyond the intermediary was actually reached.
  sources: <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

## Fp Rule

- **A port forward or tunnel bound to the loopback interface is not a pivot channel and cannot be reached by the attacker.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where an SSH client-side forward plus a local relay on the tester box chains the loopback listener into an externally reachable proxy.
  sources: <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>
- **An SSH or SOCKS tunnel inside the estate is not attacker ingress unless traffic entered from an address the client does not control.**  
  `under_review` · score 0.844 · disproved by: Would be wrong when the client's own sanctioned jump host relays to the assessment scope, in which case an external-looking leg may still be in-house.
  sources: <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

## Chain Link

- **A reverse-tunnel implant on a compromised host turns that host into a generic TCP forwarder reachable from attacker infrastructure, so the next link gets reachability to internal-only management services without a credential, because the packet source is the internal host itself.**  
  `high_confidence` · score 0.899 · disproved by: If the internal service authenticates every request regardless of source, or egress filtering blocks the implant's outbound channel, or the tunnel is bound to a fixed destination that excludes the service being attempted, the handoff produces no new reachability and the pivot chain ends at the first host.
  sources: <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>

## Known gaps

Not yet satisfied: `fp_rules`
