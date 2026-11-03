<!-- GENERATED from db/wks.db — do not edit -->
# Remote Monitoring and Management Abuse

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 22 items, 4 supported, 3 FP rules, 1 chains

RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.

**Aliases:** rmm, remote monitoring, teamviewer, anydesk, screenconnect, remote management tool, vnc

## Prerequisite

- **An exposed RMM or remote-management interface is the precondition for the class, because CISA's directive is specifically about getting networked management interfaces off the internet, so exposure of the listener, not the presence of the tool, is what makes the product remotely usable.**  
  `high_confidence` · score 0.808 · disproved by: If the listener binds only to loopback or a management VLAN and refuses connections from untrusted networks, the interface is not exposed and the RMM agent running on the host is not a finding; the mere presence of the agent, without a reachable listener, disproves this precondition.
  sources: <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/> · <https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces>

## Technique

- **Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.**  
  `high_confidence` · score 0.8415 · disproved by: If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.
  sources: <https://attack.mitre.org/techniques/T1219/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Fp Rule

- **An internet-exposed ScreenConnect instance is only exploitable below 23.9.8; a patched instance with MFA is not a finding.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong where an unpatched build sits behind an MFA-enforced control plane, since the bypass then needs the second factor.
  sources: <https://netlas.io/blog/weaponized_rmm/> · <https://www.rapid7.com/blog/post/2024/02/20/etr-high-risk-vulnerabilities-in-connectwise-screenconnect/>
- **Finding an RMM or remote-management agent running on a host is not an exposed-RMM finding unless the management listener is reachable from an untrusted network, because software installed by the defender's own deployment is the normal case and the exposure lives at the network edge.**  
  `high_confidence` · score 0.7995 · disproved by: If the management port answers a handshake from an untrusted network, the agent is genuinely exposed and this rule does not apply; conversely a host whose agent is installed, running, and management-tenant-enrolled but whose listener is not reachable is a false positive for this class.
  sources: <https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/> · <https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces>

## False-positive rules

- **Hypothesis:** An installed remote monitoring and management agent on a workstation is evidence of compromise.
  - **Invalidated by:** The install timestamp falls inside the approved deployment window, the binary matches the vendor-signed package in the software distribution system, and no management listener answered from outside the corporate network; the agent was deployed, not implanted.
  - **Rule:** An RMM agent's presence is a deployment fact, not a finding. Report it only when install time or signing identity departs from the deployment record, or when a management interface answers from a network that policy forbids.

## Related classes (via chains)

- `supply_chain` Dependency / Supply-Chain Risk (3 chains)
