# Security Misconfiguration

> surface: `web` · CWE: 16 · OWASP: A05:2021
> maturity: **mature** — 16 items, 11 supported, 4 FP rules, 1 chains

A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**Aliases:** misconfiguration, security headers, debug mode, default credentials

## Signal

- **Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.**  
  `under_review` · score 0.8105 · disproved by: If the appliance version is demonstrably patched, or no exploitation of the product has been published, patch state is not the deciding factor for this asset.
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Technique

- **A permissive sudoers entry, a world-writable service unit, or an over-permissive file permission yields root without any kernel or software vulnerability.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when the permission model forbids the escalation -- no unsafe sudoers entry, no writable unit or script the service runs, and no permissive capabilities -- leaving no configuration path to root.
  sources: <https://cwe.mitre.org/data/definitions/16.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/06.%20Post-Exploitation/32.%20Linux%20Privilege%20Escalation/Linux%20Privilege%20Escalation.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/02.%20Getting%20Started.md>
- **Public writeup evidence for misconfig: AI-driven infra-wide key discovery.**  
  `high_confidence` · score 0.7935 · disproved by: Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html> · <https://brutecat.com/articles/hacking-google-with-ai/>

## Test

- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.fp_rule.a_version_banner_alone_is_information_disclosure_not_rce) states the full boundary.
  sources: <https://docs.docker.com/engine/security/> · <https://httpd.apache.org/docs/2.4/mod/core.html>
- **To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.validation.prove_host_namespace_sharing_rather_than_assuming_from_the_manifest) states the full boundary.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.fp_rule.a_default_permissive_policy_is_not_a_vulnerability_when_it_is_the_documented_default) states the full boundary.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.bypass.a_docker_socket_mount_is_the_control_bypass_for_every_other_hardening) states the full boundary.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (misconfig.fp_rule.exposed_container_api_is_not_rce_until_a_privileged_primitive_is_shown) states the full boundary.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>

## Validation

- **A workload misconfiguration finding must be proved by the effective runtime configuration, not by the manifest alone, because whether host namespaces are actually shared is what the control is stated to disallow.**  
  `high_confidence` · score 0.863 · disproved by: The finding holds when the effective spec sets the host-namespace flags or a privileged container context and that is what runs; it is void when the manifest requests it but a policy or admission controller rewrites the effective spec before it runs, in which case the observable configuration is compliant and the manifest alone proves nothing.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>

## Fp Rule

- **A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**  
  `high_confidence` · score 0.893 · disproved by: The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163> · <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>
- **A full product and version banner in a response header is an information-disclosure finding of low severity, not an exploit, because the header alone confers no capability unless a specific matching vulnerability is shown to be reachable.**  
  `under_review` · score 0.8905 · disproved by: It escalates when the disclosed version identifies a component with a demonstrated, reachable, unpatched vulnerability on the same host, which turns the banner into a targeting aid rather than the finding itself; it stays informational when no such path is demonstrated and the only effect is that an attacker learns what they are facing.
  sources: <https://docs.docker.com/engine/security/> · <https://httpd.apache.org/docs/2.4/mod/core.html>
- **A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes.**  
  `high_confidence` · score 0.863 · disproved by: It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **Reaching a container provisioning API is only container escape rather than a mere access-control gap once the request can be shown to start a container with a host filesystem mount or privileged mode, since the sharing feature is what converts API access into host impact.**  
  `under_review` · score 0.863 · disproved by: It IS host compromise when a request creates a container that shares the host root or mounts the host directory, because the container can then alter the host filesystem; it is NOT escape when the API only permits listing or starting unprivileged isolated containers, where the impact stays inside the container boundary and the correct finding is unauthorised API access.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **Reject a misconfig finding until it is distinguished from the adjacent behaviour this class also covers. "Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical." and "They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.4315 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "They should be seen as general hunting guidance until more is known ab" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Evidence

- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**  
  `under_review` · score 0.3765 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (misconfig.fp_rule.auto.derived) states the full boundary.

## Bypass

- **Mounting the container runtime control socket into an application container nullifies the rest of the hardening around it, because the socket grants the same authority as the daemon and the shared-directory primitive is reachable through it.**  
  `high_confidence` · score 0.863 · disproved by: It is a genuine bypass when the application process can reach the socket and issue provisioning calls, since that restores daemon-equivalent privilege; it is not when the socket is present but unreachable to the untrusted process, the runtime runs rootless, or a proxy mediates the API with its own authorisation — in those cases the daemon privilege is not actually delegated.
  sources: <https://docs.docker.com/engine/security/> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>

## False-positive rules

- **Hypothesis:** Every path on the API host returns an internal server error, therefore the service is misconfigured
  - **Invalidated by:** All paths return the same development fallback response regardless of the path. Nothing is being processed server-side, so there is no error condition to trigger
  - **Rule:** A uniform 500 across every path is an application-shell fallback, not a processing error. Probe paths that do not exist: if the response is identical, there is no handler running and nothing to exploit

- **Hypothesis:** Hosts return HTTP 000 and are therefore misconfigured
  - **Invalidated by:** The addresses are excluded by edge protection or geo policy from the testing egress. No service responded on the port from anywhere reachable, so there is no running service to be misconfigured
  - **Rule:** HTTP 000 means the connection never completed - it is an egress or edge-policy block, not a finding about the service. Record it as untested and re-probe from a different egress before making any claim
