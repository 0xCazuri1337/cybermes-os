<!-- GENERATED from db/wks.db — do not edit -->
# Tunneling and Pivoting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 12 items, 6 supported, 1 FP rules, 1 chains

A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.

**Aliases:** tunneling, tunnelling, pivoting, socks, socks proxy, port forwarding, proxy, chisel, reverse tunnel

## Technique

- **A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.**  
  `high_confidence` · score 0.853 · disproved by: If egress from the compromised segment is filtered such that no permitted-protocol channel to an attacker-controlled or third host can carry an inner session, and no dual-homed host bridges the segments, then the tunnel cannot reintroduce the forbidden reachability.
  sources: <https://attack.mitre.org/techniques/T1090/> · <https://www.rfc-editor.org/rfc/rfc4459.html>
- **A pivot is established by tunnelling traffic for a second network segment through the already-compromised host, which carries no credentials of its own.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the compromised host cannot open outbound connections to the second segment, or no listener can be bound on the far side, so the tunnel never carries traffic.
  sources: <https://attack.mitre.org/techniques/T1090/> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/04.%20Exploitation/20.%20Pivoting%2C%20Tunneling%20%26%20Port%20Forwarding/Pivoting%2C%20Tunneling%20%26%20Port%20Forwarding.md>
- **Using one compromised machine to access another is called pivoting and allows us to access networks and resources that are not directly accessible to us through the compromised host.**  
  `high_confidence` · score 0.788 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Using one compromised machine to access another is called pivoting and allows us”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- **Tunneling is a technique that allows us to encapsulate traffic within another protocol so that it looks like a benign traffic stream.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Tunneling is a technique that allows us to encapsulate traffic within another pr”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>

## Fp Rule

- **A port forward or tunnel bound to the loopback interface is not a pivot channel and cannot be reached by the attacker.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where an SSH client-side forward plus a local relay on the tester box chains the loopback listener into an externally reachable proxy.
  sources: <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

## Chain Link

- **A reverse-tunnel implant on a compromised host turns that host into a generic TCP forwarder reachable from attacker infrastructure, so the next link gets reachability to internal-only management services without a credential, because the packet source is the internal host itself.**  
  `high_confidence` · score 0.899 · disproved by: If the internal service authenticates every request regardless of source, or egress filtering blocks the implant's outbound channel, or the tunnel is bound to a fixed destination that excludes the service being attempted, the handoff produces no new reachability and the pivot chain ends at the first host.
  sources: <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>

## Known gaps

Not yet satisfied: `fp_rules`
