# Security Misconfiguration

## Definition

A deployable default or an absent hardening control leaves a capability the design assumed was closed.

- **CWE:** 16
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["misconfiguration", "security headers", "debug mode", "default credentials"]

Canonical home for `misconfig`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.**

Where appliances sit on the public edge, patch state is the first question to answer because the same products appear repeatedly in exploited-in-the-wild advisories. For a hunter this makes fingerprinting versions and patch state a primary signal: it identifies reachable weakness before any payload is attempted, and it lets a mundane patch-gap outrank a novel finding on the same asset when remediation is the goal. Published exploitation references also confirm the attack surface is real, which raises confidence that a similar exposure on a sibling asset is worth reporting.

*Disproof:* If the appliance version is demonstrably patched, or no exploitation of the product has been published, patch state is not the deciding factor for this asset.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**

Derived from misconfig.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (misconfig.fp_rule.auto.derived) states the full boundary.

## Exploitation

**It does not indicate successful exploitation on patched devices.**

dating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Queries 
 This query looks for CVE-2026-88771 log poisoning. It does not indicate successful exploitation on patched devices. Unpatched devices will lead to execution if this log poisoning is present on a system. 

 
 
 
 
 
 
dataset = citrix_adc_raw 
 
| filter _raw_log contains "pitboss" 
 
| alter log_type = arrayindex(regextract(_raw_log, " ]+>(?:[A-Za-z]{3}[ ]+[0-9]{1,2}[ ]+|[ ]+[0-9]{2}/[0-9]{2}/[0-9]{4}:)[0-9]{2}:[0-9]{2}:[0-9]{2}.+default ([\w]+)"), 0), 
 
log_sub_type = arrayindex(regextract(_raw_log, " ]+>(?:

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".

**It does not indicate successful exploitation on patched devices.**

dating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Queries 
 This query looks for CVE-2026-88771 log poisoning. It does not indicate successful exploitation on patched devices. Unpatched devices will lead to execution if this log poisoning is present on a system. 

 
 
 
 
 
 
dataset = citrix_adc_raw 
 
| filter _raw_log contains "pitboss" 
 
| alter log_type = arrayindex(regextract(_raw_log, " ]+>(?:[A-Za-z]{3}[ ]+[0-9]{1,2}[ ]+|[ ]+[0-9]{2}/[0-9]{2}/[0-9]{4}:)[0-9]{2}:[0-9]{2}:[0-9]{2}.+default ([\w]+)"), 0), 
 
log_sub_type = arrayindex(regextract(_raw_log, " ]+>(?:

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".

**The grep -q guard prevents duplicate injection if the persistence mechanism is run again.**

lias: /logon/LogonPoint/custom/receiver.min.css → web shell 
 Regex alias: /logon/LogonPoint/custom/receiver.min. .css → web shell (any hex suffix) 
 
 
 
 The CSS filename disguise is deliberate. Browser developer tools, web application firewall logs and blue team analysts watching HTTP traffic will see what looks like a versioned CSS asset load, which is completely normal for a web application. The grep -q guard prevents duplicate injection if the persistence mechanism is run again. 
 Enable PHP Engine 
 The perl -pi -e 's/php_flag engine off/php_flag engine on /' /etc/httpd.conf one-liner substitutes php_flag engine off with php_flag engine on in httpd.conf to enable PHP, which is required for the web shell to execute. NetScaler's Apache config ships with php_flag engine off to disable PHP execution globally as a security hardening measure. 
 Reload Apache Using Updated Con

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".

**The grep -q guard prevents duplicate injection if the persistence mechanism is run again.**

lias: /logon/LogonPoint/custom/receiver.min.css → web shell 
 Regex alias: /logon/LogonPoint/custom/receiver.min. .css → web shell (any hex suffix) 
 
 
 
 The CSS filename disguise is deliberate. Browser developer tools, web application firewall logs and blue team analysts watching HTTP traffic will see what looks like a versioned CSS asset load, which is completely normal for a web application. The grep -q guard prevents duplicate injection if the persistence mechanism is run again. 
 Enable PHP Engine 
 The perl -pi -e 's/php_flag engine off/php_flag engine on /' /etc/httpd.conf one-liner substitutes php_flag engine off with php_flag engine on in httpd.conf to enable PHP, which is required for the web shell to execute. NetScaler's Apache config ships with php_flag engine off to disable PHP execution globally as a security hardening measure. 
 Reload Apache Using Updated Con

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".

**In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**

quested the same file, /admin_ui/common/css/ns/ui.css . Nearly two hours after that second request, 77.83.199[.]39 requested /vpn/js/rdx/core/lang/rdx_en.json.gz . These requests are consistent with version fingerprinting. 
 On August 21 and 22, these two hosts and 78.47.24[.]217 sent the same requests to more than 100 other systems. 
 CVE-2026-88772: DTLS Exploitation To .deb Webshell Activity 
 In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. This malicious packet causes memory corruption or a crash that can lead to either code execution or denial of service. 
 Between September 4 and 24, the threat actor repeatedly requested files from the appliance's /vpn/scripts/linux/ folder. This folder normally hosts Citrix client installation packages. The threat actor also used this folder to host their web shells. 
 The threat actor rotated i

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".

**In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**

quested the same file, /admin_ui/common/css/ns/ui.css . Nearly two hours after that second request, 77.83.199[.]39 requested /vpn/js/rdx/core/lang/rdx_en.json.gz . These requests are consistent with version fingerprinting. 
 On August 21 and 22, these two hosts and 78.47.24[.]217 sent the same requests to more than 100 other systems. 
 CVE-2026-88772: DTLS Exploitation To .deb Webshell Activity 
 In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. This malicious packet causes memory corruption or a crash that can lead to either code execution or denial of service. 
 Between September 4 and 24, the threat actor repeatedly requested files from the appliance's /vpn/scripts/linux/ folder. This folder normally hosts Citrix client installation packages. The threat actor also used this folder to host their web shells. 
 The threat actor rotated i

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".

**They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**

he following:
 
 A NetScaler VPX instance snapshot 
 Logs on remote syslog servers and NetScaler Console 
 A technical support bundle 
 A packet engine core dump 
 
 
 Hunt for the following:
 
 Signs of suspicious administrative sessions 
 Unexpected outbound connections 
 Unexplained gaps in logging 
 
 
 
 Note: These are not TTPs we have observed specifically related to these vulnerabilities. They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. 
 
 Update and patch to the latest versions 
 
 Note: Updating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Quer

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".

**They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**

he following:
 
 A NetScaler VPX instance snapshot 
 Logs on remote syslog servers and NetScaler Console 
 A technical support bundle 
 A packet engine core dump 
 
 
 Hunt for the following:
 
 Signs of suspicious administrative sessions 
 Unexpected outbound connections 
 Unexplained gaps in logging 
 
 
 
 Note: These are not TTPs we have observed specifically related to these vulnerabilities. They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. 
 
 Update and patch to the latest versions 
 
 Note: Updating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Quer

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".

**The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**

specified file path with optional append mode 
 info command returns the PHP version in the format php=PHP_VERSION\nns=4 
 
 CVE-2026-88771: Three Stage Command Injection Exploit to Web Shell Execution 
 On September 21, an actor from 77.83.199[.]39 , 78.47.24[.]217 and 139.180.152[.]138 dropped a PHP web shell in a three-stage process against a U.S.-based target’s NetScaler devices. 
 Stage 1 
 The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. The NetScaler device sends back a 404 error as expected, but this User-Agent string is added to the /var/log/httpaccess-vpn.log . 
 Stage 2 
 The attacker submits a login request that includes additional text that is logged as a failure message to /var/log/ns.log as: 
 pitboss PPE missed too many heartbeatsNSPPE; 
 Eventually this ns.log file will be processed by the vulnerable Perl script at /ne

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".

**The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**

specified file path with optional append mode 
 info command returns the PHP version in the format php=PHP_VERSION\nns=4 
 
 CVE-2026-88771: Three Stage Command Injection Exploit to Web Shell Execution 
 On September 21, an actor from 77.83.199[.]39 , 78.47.24[.]217 and 139.180.152[.]138 dropped a PHP web shell in a three-stage process against a U.S.-based target’s NetScaler devices. 
 Stage 1 
 The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. The NetScaler device sends back a 404 error as expected, but this User-Agent string is added to the /var/log/httpaccess-vpn.log . 
 Stage 2 
 The attacker submits a login request that includes additional text that is logged as a failure message to /var/log/ns.log as: 
 pitboss PPE missed too many heartbeatsNSPPE; 
 Eventually this ns.log file will be processed by the vulnerable Perl script at /ne

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".

**Public writeup evidence for misconfig: AI-driven infra-wide key discovery.**

HARVESTED FROM bugbountydaily RSS -> https://brutecat.com/articles/hacking-google-with-ai/
Reason it matters: AI-driven infra-wide key discovery.

Many APIs like drivefrontend-pa.googleapis.com require a more complete version of Google's FPA v2 authorization header that embeds user identifiers like email addresses within the hash.

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

**A permissive sudoers entry, a world-writable service unit, or an over-permissive file permission yields root without any kernel or software vulnerability.**

In practice on HTB this shows up as: | `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Execute a command on an uploaded webshell |
| **Privilege Escalation** |  |
| `./linpeas.sh` | Run `linpeas` script to enumerate remote server |
| `sudo -l` | List available `sudo` privileges |
| `sudo -u user /bin/echo Hello World!` | Run a command with `sudo` |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/02. Getting Started.md (929 words, classified network).

*Disproof:* Refuted when the permission model forbids the escalation -- no unsafe sudoers entry, no writable unit or script the service runs, and no permissive capabilities -- leaving no configuration path to root.

## Variations

**Mounting the container runtime control socket into an application container nullifies the rest of the hardening around it, because the socket grants the same authority as the daemon and the shared-directory primitive is reachable through it.**

Mechanism: Mounting the container runtime control socket into an application container nullifies the rest of the hardening around it, because the socket grants the same authority as the daemon and the shared-directory primitive is reachable through it. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is a genuine bypass when the application process can reach the socket and issue provisioning calls, since that restores daemon-equivalent privilege; it is not when the socket is present but unreachable to the untrusted process, the runtime runs rootless, or a proxy mediates the API with its own authorisation — in those cases the daemon privilege is not actually delegated.

*Disproof:* It is a genuine bypass when the application process can reach the socket and issue provisioning calls, since that restores daemon-equivalent privilege; it is not when the socket is present but unreachable to the untrusted process, the runtime runs rootless, or a proxy mediates the API with its own authorisation — in those cases the daemon privilege is not actually delegated.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.misconfig.auto.01` — misconfig: observe, exercise, confirm (goal: `Establish, exercise and confirm a misconfig condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes.**

Mechanism: A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.

*Disproof:* It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.

**A full product and version banner in a response header is an information-disclosure finding of low severity, not an exploit, because the header alone confers no capability unless a specific matching vulnerability is shown to be reachable.**

Mechanism: A full product and version banner in a response header is an information-disclosure finding of low severity, not an exploit, because the header alone confers no capability unless a specific matching vulnerability is shown to be reachable. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It escalates when the disclosed version identifies a component with a demonstrated, reachable, unpatched vulnerability on the same host, which turns the banner into a targeting aid rather than the finding itself; it stays informational when no such path is demonstrated and the only effect is that an attacker learns what they are facing.

*Disproof:* It escalates when the disclosed version identifies a component with a demonstrated, reachable, unpatched vulnerability on the same host, which turns the banner into a targeting aid rather than the finding itself; it stays informational when no such path is demonstrated and the only effect is that an attacker learns what they are facing.

**Reject a misconfig finding until it is distinguished from the adjacent behaviour this class also covers. "Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical." and "They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.

Adjacent behaviour that produces the same observable result: They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "They should be seen as general hunting guidance until more is known ab" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reaching a container provisioning API is only container escape rather than a mere access-control gap once the request can be shown to start a container with a host filesystem mount or privileged mode, since the sharing feature is what converts API access into host impact.**

Mechanism: Reaching a container provisioning API is only container escape rather than a mere access-control gap once the request can be shown to start a container with a host filesystem mount or privileged mode, since the sharing feature is what converts API access into host impact. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS host compromise when a request creates a container that shares the host root or mounts the host directory, because the container can then alter the host filesystem; it is NOT escape when the API only permits listing or starting unprivileged isolated containers, where the impact stays inside the container boundary and the correct finding is unauthorised API access.

*Disproof:* It IS host compromise when a request creates a container that shares the host root or mounts the host directory, because the container can then alter the host filesystem; it is NOT escape when the API only permits listing or starting unprivileged isolated containers, where the impact stays inside the container boundary and the correct finding is unauthorised API access.

**A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**

The observation is an unauthenticated administrative interface on a device in the field, which is usually filed as authentication removed or a backdoor web shell installed. On a large class of consumer and SOHO devices it is simply the shipping behaviour: notably missing from the initial setup wizard is any sort of web portal username and login, and there is also no subsequent window requiring these to be set, so the router will fully function and will login anyone on the local network who can talk to it on the LAN side, giving them full administrative access. The setting of a web portal password requires extra configuration in an Administration tab and no warning is ever given to the owners. That means an asset-management or vulnerability scan that reports 'no authentication on admin interface' on such a device is reporting the default, not a change in state. Scanner output is even weaker evidence here than usual, because template-based tools run a lighter detection mode that only verifies the presence of services without conducting deeper security assessments, so a hit may mean only that an endpoint answered. The distinguishing test is provenance: check the device's setup flow and provisioning record for whether a portal credential was ever requested. If the wizard never asked, the finding is an inventory and hardening item (change the default, restrict LAN reachability), not an incident.

*Disproof:* The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
**Hypothesis:** Hosts return HTTP 000 and are therefore misconfigured
- Invalidated by: The addresses are excluded by edge protection or geo policy from the testing egress. No service responded on the port from anywhere reachable, so there is no running service to be misconfigured
- **Rejection rule:** HTTP 000 means the connection never completed - it is an egress or edge-policy block, not a finding about the service. Record it as untested and re-probe from a different egress before making any claim

**Hypothesis:** Every path on the API host returns an internal server error, therefore the service is misconfigured
- Invalidated by: All paths return the same development fallback response regardless of the path. Nothing is being processed server-side, so there is no error condition to trigger
- **Rejection rule:** A uniform 500 across every path is an application-shell fallback, not a processing error. Probe paths that do not exist: if the response is identical, there is no handler running and nothing to exploit

## Validation

**A workload misconfiguration finding must be proved by the effective runtime configuration, not by the manifest alone, because whether host namespaces are actually shared is what the control is stated to disallow.**

Mechanism: A workload misconfiguration finding must be proved by the effective runtime configuration, not by the manifest alone, because whether host namespaces are actually shared is what the control is stated to disallow. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The finding holds when the effective spec sets the host-namespace flags or a privileged container context and that is what runs; it is void when the manifest requests it but a policy or admission controller rewrites the effective spec before it runs, in which case the observable configuration is compliant and the manifest alone proves nothing.

*Disproof:* The finding holds when the effective spec sets the host-namespace flags or a privileged container context and that is what runs; it is void when the manifest requests it but a policy or admission controller rewrites the effective spec before it runs, in which case the observable configuration is compliant and the manifest alone proves nothing.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from misconfig.fp_rule.a_version_banner_alone_is_information_disclosure_not_rce, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.fp_rule.a_version_banner_alone_is_information_disclosure_not_rce) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from misconfig.validation.prove_host_namespace_sharing_rather_than_assuming_from_the_manifest, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.validation.prove_host_namespace_sharing_rather_than_assuming_from_the_manifest) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from misconfig.fp_rule.a_default_permissive_policy_is_not_a_vulnerability_when_it_is_the_documented_default, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.fp_rule.a_default_permissive_policy_is_not_a_vulnerability_when_it_is_the_documented_default) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from misconfig.bypass.a_docker_socket_mount_is_the_control_bypass_for_every_other_hardening, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.bypass.a_docker_socket_mount_is_the_control_bypass_for_every_other_hardening) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from misconfig.fp_rule.exposed_container_api_is_not_rce_until_a_privileged_primitive_is_shown, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.fp_rule.exposed_container_api_is_not_rce_until_a_privileged_primitive_is_shown) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.trailofbits.com** (writeup)
  - <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **brutecat.com** (writeup)
  - <https://brutecat.com/articles/hacking-google-with-ai/>
- **cheatsheetseries.owasp.org** (taxonomy)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/16.html>
- **docs.docker.com** (research)
  - <https://docs.docker.com/engine/security/>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>
- **httpd.apache.org** (writeup)
  - <https://httpd.apache.org/docs/2.4/mod/core.html>
- **kubernetes.io** (writeup)
  - <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/06.%20Post-Exploitation/32.%20Linux%20Privilege%20Escalation/Linux%20Privilege%20Escalation.md>
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/02.%20Getting%20Started.md>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163>
- **unit42.paloaltonetworks.com** (writeup)
  - <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
