# Methodology — Remote Monitoring and Management Abuse

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class exposed_rmm --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**An exposed RMM or remote-management interface is the precondition for the class, because CISA's directive is specifically about getting networked management interfaces off the internet, so exposure of the listener, not the presence of the tool, is what makes the product remotely usable.**

The primitive gives you: an authenticated-or-not remote management channel on a host. Tenable's position is that CISA Binding Operational Directive 23-02 instructs agencies to get management interfaces off the internet in order to mitigate risk, which defines exposure at the network edge rather than at the agent, and that exposed management interfaces are valuable entry points for attackers. The precondition the next link needs is that a management session, once established, is a full command channel rather than a read-only console: Microsoft describes a campaign where remote control established via RMM tools was then used to run PowerShell and silently install a malicious MSI, which is the shape the next link consumes. Observation that proves this segment: the management listener answers from an untrusted network and the established session accepts a command that changes host state.

- *Disproof:* If the listener binds only to loopback or a management VLAN and refuses connections from untrusted networks, the interface is not exposed and the RMM agent running on the host is not a finding; the mere presence of the agent, without a reachable listener, disproves this precondition.
- *Evidence:* high_confidence — [microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/); [tenable.com](https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.**

The defining property of an RMM tool is exactly the security problem: it grants remote control of a computer as if the operator were sitting at it, inheriting that user or software's permissions. So the RMM agent is a privileged access path by design, installed to operate across network controls — which is why it is a high-value target rather than a utility. The two questions to ask are therefore about the console, not the endpoint: is the RMM management interface reachable from where it should not be, and is its authentication strong enough to resist the credential attacks documented as common against remote management surfaces. Vendor and group reporting in ATT&CK (tooling used to deploy malware from an already-compromised host) confirms the operational reality that these consoles are used as distribution and access infrastructure. Multi-factor authentication on the console is the specific control that changes the exposure.

- *Disproof:* If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1219/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An internet-exposed ScreenConnect instance is only exploitable below 23.9.8; a patched instance with MFA is not a finding.**

Discard when the exposed instance was already upgraded: the Rapid7 analysis states all versions before 23.9.8 are vulnerable to the authentication bypass and path traversal issues, so a current build with enforcement enabled has no auth bypass. It survives when the instance answered on a vulnerable version and a new administrative account could be created unauthenticated.

- *Disproof:* Would be wrong where an unpatched build sits behind an MFA-enforced control plane, since the bypass then needs the second factor.
- *Evidence:* high_confidence — [netlas.io](https://netlas.io/blog/weaponized_rmm/); [rapid7.com](https://www.rapid7.com/blog/post/2024/02/20/etr-high-risk-vulnerabilities-in-connectwise-screenconnect/)

**Finding an RMM or remote-management agent running on a host is not an exposed-RMM finding unless the management listener is reachable from an untrusted network, because software installed by the defender's own deployment is the normal case and the exposure lives at the network edge.**

The reason this is an FP class rather than a real finding: Microsoft observed a campaign distributing a masqueraded RMM installer through meeting invitations and PDF-themed lures, so the presence of the agent is exactly what both a legitimate deployment and an attack look like from the endpoint alone, and the deceptive filename is what distinguishes them rather than the running process. Tenable's exposure framing is the same: the directive is to get management interfaces off the internet, which places the control on reachability, not on the software inventory. The test that resolves it: from an untrusted source network, attempt a protocol handshake against the vendor's management port. A refusal or filtered packet proves there is no exposure and the agent is a false positive; a completed handshake means the exposure is real and the finding stands, regardless of how the agent got there.

- *Disproof:* If the management port answers a handshake from an untrusted network, the agent is genuinely exposed and this rule does not apply; conversely a host whose agent is installed, running, and management-tenant-enrolled but whose listener is not reachable is a false positive for this class.
- *Evidence:* high_confidence — [microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/); [tenable.com](https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
