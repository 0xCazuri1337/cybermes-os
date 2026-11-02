# Remote Monitoring and Management Abuse

## Definition

RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["rmm", "remote monitoring", "teamviewer", "anydesk", "screenconnect", "remote management tool", "vnc"]

Canonical home for `exposed_rmm`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**An exposed RMM or remote-management interface is the precondition for the class, because CISA's directive is specifically about getting networked management interfaces off the internet, so exposure of the listener, not the presence of the tool, is what makes the product remotely usable.**

The primitive gives you: an authenticated-or-not remote management channel on a host. Tenable's position is that CISA Binding Operational Directive 23-02 instructs agencies to get management interfaces off the internet in order to mitigate risk, which defines exposure at the network edge rather than at the agent, and that exposed management interfaces are valuable entry points for attackers. The precondition the next link needs is that a management session, once established, is a full command channel rather than a read-only console: Microsoft describes a campaign where remote control established via RMM tools was then used to run PowerShell and silently install a malicious MSI, which is the shape the next link consumes. Observation that proves this segment: the management listener answers from an untrusted network and the established session accepts a command that changes host state.

*Disproof:* If the listener binds only to loopback or a management VLAN and refuses connections from untrusted networks, the interface is not exposed and the RMM agent running on the host is not a finding; the mere presence of the agent, without a reachable listener, disproves this precondition.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.**

The defining property of an RMM tool is exactly the security problem: it grants remote control of a computer as if the operator were sitting at it, inheriting that user or software's permissions. So the RMM agent is a privileged access path by design, installed to operate across network controls — which is why it is a high-value target rather than a utility. The two questions to ask are therefore about the console, not the endpoint: is the RMM management interface reachable from where it should not be, and is its authentication strong enough to resist the credential attacks documented as common against remote management surfaces. Vendor and group reporting in ATT&CK (tooling used to deploy malware from an already-compromised host) confirms the operational reality that these consoles are used as distribution and access infrastructure. Multi-factor authentication on the console is the specific control that changes the exposure.

*Disproof:* If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ci-credential-to-self-propagating-poisoned-artifact` — CI credential exposure to self-propagating poisoned artifact to re-executing host delivery (goal: `persistent_host_execution`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Finding an RMM or remote-management agent running on a host is not an exposed-RMM finding unless the management listener is reachable from an untrusted network, because software installed by the defender's own deployment is the normal case and the exposure lives at the network edge.**

The reason this is an FP class rather than a real finding: Microsoft observed a campaign distributing a masqueraded RMM installer through meeting invitations and PDF-themed lures, so the presence of the agent is exactly what both a legitimate deployment and an attack look like from the endpoint alone, and the deceptive filename is what distinguishes them rather than the running process. Tenable's exposure framing is the same: the directive is to get management interfaces off the internet, which places the control on reachability, not on the software inventory. The test that resolves it: from an untrusted source network, attempt a protocol handshake against the vendor's management port. A refusal or filtered packet proves there is no exposure and the agent is a false positive; a completed handshake means the exposure is real and the finding stands, regardless of how the agent got there.

*Disproof:* If the management port answers a handshake from an untrusted network, the agent is genuinely exposed and this rule does not apply; conversely a host whose agent is installed, running, and management-tenant-enrolled but whose listener is not reachable is a false positive for this class.

**A legitimately installed RMM agent on a host is not compromise; discard the finding when no unauthorised deployment was shown.**

Discard when the report rests on the tool being present and running: the joint advisory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's. It survives when the agent was installed during the engagement window, or connects to attacker-controlled relay infrastructure.

*Disproof:* Would be wrong where the installed agent version is one of the known-vulnerable builds and is internet-reachable, since that is an exposure in itself.

**An internet-exposed ScreenConnect instance is only exploitable below 23.9.8; a patched instance with MFA is not a finding.**

Discard when the exposed instance was already upgraded: the Rapid7 analysis states all versions before 23.9.8 are vulnerable to the authentication bypass and path traversal issues, so a current build with enforcement enabled has no auth bypass. It survives when the instance answered on a vulnerable version and a new administrative account could be created unauthenticated.

*Disproof:* Would be wrong where an unpatched build sits behind an MFA-enforced control plane, since the bypass then needs the second factor.
**Hypothesis:** An installed remote monitoring and management agent on a workstation is evidence of compromise.
- Invalidated by: The install timestamp falls inside the approved deployment window, the binary matches the vendor-signed package in the software distribution system, and no management listener answered from outside the corporate network; the agent was deployed, not implanted.
- **Rejection rule:** An RMM agent's presence is a deployment fact, not a finding. Report it only when install time or signing identity departs from the deployment record, or when a management interface answers from a network that policy forbids.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1219/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **cisa.gov** (advisory)
  - <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
  - <https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/>
- **netlas.io** (writeup)
  - <https://netlas.io/blog/weaponized_rmm/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/2024/02/20/etr-high-risk-vulnerabilities-in-connectwise-screenconnect/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
