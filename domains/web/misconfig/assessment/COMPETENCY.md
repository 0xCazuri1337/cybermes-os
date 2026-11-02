# Methodology — Security Misconfiguration

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class misconfig --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**References.** CWE-16 · A05:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Misconfigured reverse proxies or CDNs that exclude attacker-controlled headers from the cache key, such as a Host header whose port is unkeyed, allow web cache poisoning and cache-deception attacks that redirect or poison responses for all users.**

Some caching systems parse headers and exclude the port from the cache key; when the Host header is dynamically used to generate a redirect URL, an attacker can add an arbitrary port to the request and redirect all users who browse the home page to a dud port, effectively taking the page down until the cache expires. The same unkeyed-header class applies to any header that the caching layer omits from the cache key, enabling web cache poisoning and deception with popular HTTP servers and CDNs under their default configurations. This is explicitly a configuration problem: the cache key must include every header that the application or a proxy reflects into a cacheable response.

- *Disproof:* If the proxy includes all attacker-influenced headers in the cache key and the backend deduplicates or validates them, the poisoning surface is closed. The attack also only succeeds when the application both reflects attacker input into a cacheable response and serves shared content to multiple users, so cache poisoning is not possible on personalized or non-cacheable pages.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9111.html)

**Default credentials, leftover sample applications, and skipped hardening turn a correctly written application into a vulnerable one even when the code is clean.**

Security misconfiguration is a deployment bug, not a code defect: the same application code can ship with its development configuration (verbose errors, debug console, default credentials, enabled features, directory listing) when the hardening process is skipped, and configuration drifts over time, because a setting that was correct at launch is loosened during an incident and never tightened again. The application may be vulnerable when the stack lacks appropriate hardening, default accounts and their passwords remain enabled and unchanged, error handling reveals stack traces, the security settings in application servers, frameworks, libraries and databases are not set to secure values, the server sends no security headers or directives, or the software is out of date. Without a repeatable, automated configuration process, systems are at a higher risk.

- *Disproof:* A hardened deployment with generic error pages, no default accounts, debug features disabled, sample applications removed, a minimal platform, and a repeatable automated hardening process is not vulnerable to this class. The risk is specifically the configuration that shipped, not the code.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/16.html); [top10.owasp.org](https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/index.html)

**A permissive sudoers entry, a world-writable service unit, or an over-permissive file permission yields root without any kernel or software vulnerability.**

In practice on HTB this shows up as: | `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Execute a command on an uploaded webshell |
| **Privilege Escalation** |  |
| `./linpeas.sh` | Run `linpeas` script to enumerate remote server |
| `sudo -l` | List available `sudo` privileges |
| `sudo -u user /bin/echo Hello World!` | Run a command with `sudo` |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/02. Getting Started.md (929 words, classified network).

- *Disproof:* Refuted when the permission model forbids the escalation -- no unsafe sudoers entry, no writable unit or script the service runs, and no permissive capabilities -- leaving no configuration path to root.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/16.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/02.%20Getting%20Started.md)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**

The observation is an unauthenticated administrative interface on a device in the field, which is usually filed as authentication removed or a backdoor web shell installed. On a large class of consumer and SOHO devices it is simply the shipping behaviour: notably missing from the initial setup wizard is any sort of web portal username and login, and there is also no subsequent window requiring these to be set, so the router will fully function and will login anyone on the local network who can talk to it on the LAN side, giving them full administrative access. The setting of a web portal password requires extra configuration in an Administration tab and no warning is ever given to the owners. That means an asset-management or vulnerability scan that reports 'no authentication on admin interface' on such a device is reporting the default, not a change in state. Scanner output is even weaker evidence here than usual, because template-based tools run a lighter detection mode that only verifies the presence of services without conducting deeper security assessments, so a hit may mean only that an endpoint answered. The distinguishing test is provenance: check the device's setup flow and provisioning record for whether a portal credential was ever requested. If the wizard never asked, the finding is an inventory and hardening item (change the default, restrict LAN reachability), not an incident.

- *Disproof:* The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163)

**A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes.**

Mechanism: A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.

- *Disproof:* It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.
- *Evidence:* high_confidence — [docs.docker.com](https://docs.docker.com/engine/security/); [kubernetes.io](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
