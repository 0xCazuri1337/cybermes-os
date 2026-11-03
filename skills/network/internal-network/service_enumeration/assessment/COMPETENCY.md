# Methodology — Service Enumeration and Fingerprinting

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class service_enumeration --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A service's announcement identifies its implementation and often its version, which selects the technique that applies to it.

**References.** CWE-200

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Full TCP port scanning with service version detection is the entry step that establishes which attack surface exists before any technique is attempted.**

In practice on HTB this shows up as: ------
There are cases in which administrators block specific subnets from different regions in principle. This prevents any access to the target network. Another example is when IPS should block us. For this reason, the Decoy scanning method (`-D`) is the right choice. With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (`RND`) a specific number (for example: `5`) of IP addresses separated by a colon (`:`). Our real IP address is then randomly placed between the generated IP addresses. In the next example, our real IP address is therefore placed in the second position. Another critical point is that the decoys must be alive. Otherwise, the service on the target may be unreachable due to SYN-flooding security mechanisms.
#### Scan by Using Decoys

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/02. Information Gathering/10. Network Enumeration with Nmap/Network Enumeration with Nmap.md (12220 words, classified network).

- *Disproof:* Refuted when the target is unreachable or filters the scan so that no port state is observable, in which case the scan yields no attack surface at all.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1046/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/200.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10.%20Network%20Enumeration%20with%20Nmap/Network%20Enumeration%20with%20Nmap.md)

**Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.**

Enumeration is a selection step, not an end. The scan output — open ports, service banners, OS fingerprints — is what tells you whether NTLM relay, SMB signing, WinRM or an exposed RDP listener is a candidate at all, so a scan that produces only port numbers has not yet produced anything actionable. ATT&CK describes the acquisition step as port, vulnerability and wordlist scans, and the vendors listed show both halves in practice (host scanners, and malware that scans to enumerate active services). The operational discipline: record the banner, not just the open port, because the technique that applies is a property of the service implementation and version. Also correlate with the assigned function of the host — an unexpected high-value service on a host whose role does not need it is the finding, not the scan itself. IANA service names are the reference for what a port is supposed to be, which makes an unexpected name a concrete observation rather than a judgement call.

- *Disproof:* If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/300.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6335.html)

**Nmap service version detection with -sV probes open ports to identify the running service and its version.**

Running nmap -sV against a target sends service-specific probes to open ports and matches responses against a signature database. Increasing --version-intensity to 9 sends more probes, identifying services that disguise themselves or run on non-standard ports. Version data feeds vulnerability research and patch-level assessment.

- *Disproof:* Ports are filtered or closed, or version detection returns no match for any service.
- *Evidence:* high_confidence — [dev.to](https://dev.to/alvinseyidov/networking-for-cybersecurity-part-5-scanning-enumeration-fingerprinting-344p); [github.com](https://github.com/jesse12-21/nmap-network-recon/blob/main/README.md)

**A full port scan with nmap -p- -sV identifies all 65535 ports and the services running on each, providing complete attack surface visibility.**

Scanning all ports with -p- followed by -sV ensures no service on a non-standard port is missed. Verbose mode (-v) shows open ports as they are found, allowing real-time analysis. This is slower but necessary for thorough internal reconnaissance.

- *Disproof:* All 65535 ports are filtered by a firewall, or scan time constraints prevent full coverage.
- *Evidence:* supported — [dev.to](https://dev.to/alvinseyidov/networking-for-cybersecurity-part-5-scanning-enumeration-fingerprinting-344p); [sammyha.github.io](https://sammyha.github.io/notes/CPTS/Nmap/Service%20Enumeration/)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.**

Enumerate who actually has RDP access to which hosts before judging any session -- in a typical domain a large share of users can RDP to a common file or build host, and that shared access is what makes credential spraying productive, because one sprayed password unlocks one session on a host many accounts can reach. The confirming test then has two halves: the session's account appears in the enumerated RDP-access set for that destination, and the credential it used was obtained by a spray, a roast or a hash replay rather than issued to the operator. Both halves present means reportable; either alone means the session is expected behaviour that happens to look like an intrusion.

- *Disproof:* Proof the claim wrong would be a session where the account holds no enumerated RDP right to the destination yet the session succeeded, or one where the credential was legitimately issued to the operator but the session still carried a non-standard channel and created a forward -- in either case rights and credential origin would not have discriminated the finding, and channel plus process evidence would have to be the deciding signal.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**RDP sessions arriving from a known administrator workstation, a sanctioned jump host, or a training lab endpoint are expected and must not be reported as exposed-service misuse.**

The lookalike is a well-known host sitting inside an otherwise clean estate: a bastion, a vendor jump host, or a lab range whose whole purpose is RDP. Every service-enumeration finding for RDP originating from these sources should be resolved against the sanctioned-endpoint list and closed, because reachability from an approved operator path is the design, not the defect. The residual check worth keeping is directional: sessions from an approved source to a destination outside the estate's service inventory are not covered by this exemption and remain reportable.

- *Disproof:* Proof the rule wrong would be a session from a sanctioned jump host that is demonstrably not sanctioned operator work -- carrying a non-standard virtual channel, running bulk transfer, or creating a port-forwarding rule on the destination -- which would mean the exemption must be conditioned on channel and process evidence rather than on source host alone.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
