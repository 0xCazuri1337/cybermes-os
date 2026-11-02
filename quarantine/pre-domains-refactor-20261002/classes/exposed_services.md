# Exposed Remote Services

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 6 items, 6 supported, 2 FP rules, 1 chains

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**Aliases:** exposed service, exposed services, remote services, internet facing service, management interface exposure

## Prerequisite

- **Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**  
  `high_confidence` · score 0.844 · disproved by: An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
  sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>

## Signal

- **An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.**  
  `high_confidence` · score 0.844 · disproved by: Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**  
  `high_confidence` · score 0.814 · disproved by: If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>

## Validation

- **A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.**  
  `high_confidence` · score 0.8715 · disproved by: Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Fp Rule

- **An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**  
  `high_confidence` · score 0.8255 · disproved by: The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>

## Chain Link

- **An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.**  
  `high_confidence` · score 0.8875 · disproved by: Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## False-positive rules

- **Hypothesis:** An SSH service listening on an unusual high TCP port is an exposed remote service finding.
  - **Invalidated by:** The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
  - **Rule:** A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Related classes (via chains)

- `smb` SMB/CIFS Abuse (2 chains)
- `lateral_movement` Lateral Movement (2 chains)

## Known gaps

Not yet satisfied: `items`
