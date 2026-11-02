# Exposed Remote Services

## Definition

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["exposed service", "exposed services", "remote services", "internet facing service", "management interface exposure"]

Canonical home for `exposed_services`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**

A hunter should inventory remote-access agents and open ports on non-IT-exposed building systems before anything else, because these are the pivot points into an otherwise segmented network, and should rank an open port as an attack path rather than as a hygiene finding. The precondition framing matters: the exposure itself is ordinary, and the severity comes from what the reachable device trusts once it is spoken to. The claim is falsified by an estate inventory showing no third-party remote access agents and no non-essential open ports on these systems.

*Disproof:* An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.**

Split RDP detections on the destination's role. A session to a workstation is routine; a session to a domain controller lands on a host whose credentials and replication rights are worth taking, so route those first and require a named-operator justification for each. Concretely, resolve every RDP session's destination against the domain controller inventory, pull the RdpCoreTS channel inventory for the ones that match, and check whether the channel set is standard or carries a bulk-transfer channel. Interactive administrative sessions to domain controllers are common enough that the signal is only meaningful when paired with channel and process evidence.

*Disproof:* Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.

## Exploitation

**An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**

Reachability is the whole variable here. A management interface that is authenticated and patched changes character completely depending on who can reach it, because every control downstream of the listener is unreachable to an adversary who cannot complete a TCP handshake to it. The correct test is therefore not 'is this service exposed' but 'is this service reachable from a segment that policy says should not reach it' — an SMTP relay reachable from the DMZ and the same relay reachable from a laptop are different findings with the same banner. Where the service is required for administration, the mitigation pattern ATT&CK recommends for the comparable WinRM case is the general one: lock down critical enclaves with separate infrastructure and restrict access with host firewall rules to specific destinations, rather than trying to harden a listener that should never have been reachable.

*Disproof:* If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `reachable-admin-service-to-relayed-credential-to-lateral` — Policy-violating administrative service reachability to relayed server credentials to lateral movement (goal: `credential_theft_and_lateral`)

## Real-World Examples

Not yet researched.

## Common False Positives

**An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**

The observation that produces this false positive is port 22 absent and SSH present on, for example, TCP 20001, which reads as an operator having moved the shell off the default port to evade detection. Measured across real internet-wide data, SSH appeared on non-standard ports nearly as often as on port 22, so a non-standard port is a population norm rather than an anomaly. A concrete benign instance is a home router whose dropbear SSH service is present and running on port TCP 0.0.0.0:20001 and serves to only allow port forwarding to enable remote cloud connections to the device's configuration service for app-based configuration. That is a vendor cloud-management tunnel: the daemon exists to forward a vendor app session, and it is reachable from the LAN side or the vendor's path by design. The distinguishing test is not the port number but the purpose: does the SSH daemon grant a general interactive shell to an arbitrary source, or does it only relay the vendor management protocol, and is the account/key set constrained to that relay? A high port with a general shell and rotating unknown host keys is a finding; a high port wired to one vendor management endpoint is inventory.

*Disproof:* The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
**Hypothesis:** An SSH service listening on an unusual high TCP port is an exposed remote service finding.
- Invalidated by: The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
- **Rejection rule:** A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Validation

**A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.**

The discriminating test: for each RDP session to a DC, establish from directory data whether the account was actually entitled to log on there, and compare that entitlement against the session's actual source and time. If the account holds no interactive logon right on that controller, the session is an access-control bypass rather than a misuse of granted rights -- a materially different finding. If it does hold the right, the finding collapses into the expected-administrator false positive and should be closed there. Enumerating that rights data is the step that separates the two, and it is the step most often skipped.

*Disproof:* Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-ldap>
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1133/>
- **claroty.com** (research)
  - <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
- **helpnetsecurity.com** (blog)
  - <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
