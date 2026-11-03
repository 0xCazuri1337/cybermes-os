<!-- GENERATED from db/wks.db — do not edit -->
# Security Misconfiguration

> surface: `web` · CWE: 16 · OWASP: A05:2021
> maturity: **mature** — 15 items, 7 supported, 4 FP rules, 1 chains

A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**Aliases:** misconfiguration, security headers, debug mode, default credentials

## Technique

- **Misconfigured reverse proxies or CDNs that exclude attacker-controlled headers from the cache key, such as a Host header whose port is unkeyed, allow web cache poisoning and cache-deception attacks that redirect or poison responses for all users.**  
  `high_confidence` · score 0.8445 · disproved by: If the proxy includes all attacker-influenced headers in the cache key and the backend deduplicates or validates them, the poisoning surface is closed. The attack also only succeeds when the application both reflects attacker input into a cacheable response and serves shared content to multiple users, so cache poisoning is not possible on personalized or non-cacheable pages.
  sources: <https://www.rfc-editor.org/rfc/rfc9111.html> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws>
- **Default credentials, leftover sample applications, and skipped hardening turn a correctly written application into a vulnerable one even when the code is clean.**  
  `high_confidence` · score 0.8255 · disproved by: A hardened deployment with generic error pages, no default accounts, debug features disabled, sample applications removed, a minimal platform, and a repeatable automated hardening process is not vulnerable to this class. The risk is specifically the configuration that shipped, not the code.
  sources: <https://cwe.mitre.org/data/definitions/16.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/index.html>
- **A permissive sudoers entry, a world-writable service unit, or an over-permissive file permission yields root without any kernel or software vulnerability.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when the permission model forbids the escalation -- no unsafe sudoers entry, no writable unit or script the service runs, and no permissive capabilities -- leaving no configuration path to root.
  sources: <https://cwe.mitre.org/data/definitions/16.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/06.%20Post-Exploitation/32.%20Linux%20Privilege%20Escalation/Linux%20Privilege%20Escalation.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/02.%20Getting%20Started.md>

## Fp Rule

- **A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**  
  `high_confidence` · score 0.893 · disproved by: The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163> · <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>
- **A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes.**  
  `high_confidence` · score 0.863 · disproved by: It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>

## Evidence

- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**  
  `high_confidence` · score 0.783 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (misconfig.fp_rule.auto.derived) states the full boundary.
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Vulnerability

- **Security misconfiguration occurs at any stack layer (servers, frameworks, cloud storage, IaC) and yields vulnerabilities from default credentials, verbose errors, missing hardening, and over-permissive permissions.**  
  `high_confidence` · score 0.8965 · disproved by: If a baseline hardening standard is enforced and verified across all environments; if no default credentials remain; if debug endpoints and unnecessary features are removed; if security headers and TLS are set to secure values; and if misconfigured resources are caught by automated scanners before deployment, the risk is neutralized. A passing automated misconfiguration check across all layers disproves an exploitable configuration flaw.
  sources: <https://cwe.mitre.org/data/definitions/16.html> · <https://owasp.github.io/DevSecOpsGuideline/2-Process/2-4-Test/2-4-5-Misconfiguration-Check/> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>

## False-positive rules

- **Hypothesis:** Every path on the API host returns an internal server error, therefore the service is misconfigured
  - **Invalidated by:** All paths return the same development fallback response regardless of the path. Nothing is being processed server-side, so there is no error condition to trigger
  - **Rule:** A uniform 500 across every path is an application-shell fallback, not a processing error. Probe paths that do not exist: if the response is identical, there is no handler running and nothing to exploit

- **Hypothesis:** Hosts return HTTP 000 and are therefore misconfigured
  - **Invalidated by:** The addresses are excluded by edge protection or geo policy from the testing egress. No service responded on the port from anywhere reachable, so there is no running service to be misconfigured
  - **Rule:** HTTP 000 means the connection never completed - it is an egress or edge-policy block, not a finding about the service. Record it as untested and re-probe from a different egress before making any claim
