# Methodology — Exposed Remote Services

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class exposed_services --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**

A hunter should inventory remote-access agents and open ports on non-IT-exposed building systems before anything else, because these are the pivot points into an otherwise segmented network, and should rank an open port as an attack path rather than as a hygiene finding. The precondition framing matters: the exposure itself is ordinary, and the severity comes from what the reachable device trusts once it is spoken to. The claim is falsified by an estate inventory showing no third-party remote access agents and no non-essential open ports on these systems.

- *Disproof:* An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
- *Evidence:* high_confidence — [claroty.com](https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures); [labs.watchtowr.com](https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**

Reachability is the whole variable here. A management interface that is authenticated and patched changes character completely depending on who can reach it, because every control downstream of the listener is unreachable to an adversary who cannot complete a TCP handshake to it. The correct test is therefore not 'is this service exposed' but 'is this service reachable from a segment that policy says should not reach it' — an SMTP relay reachable from the DMZ and the same relay reachable from a laptop are different findings with the same banner. Where the service is required for administration, the mitigation pattern ATT&CK recommends for the comparable WinRM case is the general one: lock down critical enclaves with separate infrastructure and restrict access with host firewall rules to specific destinations, rather than trying to harden a listener that should never have been reachable.

- *Disproof:* If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1133/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**

The observation that produces this false positive is port 22 absent and SSH present on, for example, TCP 20001, which reads as an operator having moved the shell off the default port to evade detection. Measured across real internet-wide data, SSH appeared on non-standard ports nearly as often as on port 22, so a non-standard port is a population norm rather than an anomaly. A concrete benign instance is a home router whose dropbear SSH service is present and running on port TCP 0.0.0.0:20001 and serves to only allow port forwarding to enable remote cloud connections to the device's configuration service for app-based configuration. That is a vendor cloud-management tunnel: the daemon exists to forward a vendor app session, and it is reachable from the LAN side or the vendor's path by design. The distinguishing test is not the port number but the purpose: does the SSH daemon grant a general interactive shell to an arbitrary source, or does it only relay the vendor management protocol, and is the account/key set constrained to that relay? A high port with a general shell and rotating unknown host keys is a finding; a high port wired to one vendor management endpoint is inventory.

- *Disproof:* The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.**

The exposure and the relay are separate findings that must be reported as one chain or as nothing. The exposure half: an administrative or remote service reachable from a network segment where policy forbids it concedes its authentication surface to that reachability - the control that failed is segmentation, and the consequence is that every authentication mechanism the service offers is now attackable from a position it was never meant to be reached from. The relay half: once such a service answers an outbound or coerced authentication, it hands its own credentials to the party that challenged it, so the exposure converts directly into a credential for the next protocol. The two published halves make this explicit on both sides: Kerberoasting needs only that a low-privileged account and a valid ticket exist to request weakened-encryption service tickets, and it does not matter whether that account actually holds access permissions for those services; separately, forced outbound authentication to an attacker-chosen SMB host returns the server's own NTLM credentials to that host. Compose them and the boundary matters twice - first the attacker needs the service to be reachable at all, and second the relayed credential must land on a service that does not enforce signing or channel binding. Test the chain by confirming reachability from the untrusted segment and then confirming an authentication exchange that returns a credential, not by confirming the port is open.

- *Disproof:* Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
