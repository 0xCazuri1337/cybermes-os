# Service-Specific Configuration Assessment

> surface: `net` · CWE: CWE-16 · OWASP: —
> maturity: **researching** — 2 items, 2 supported, 1 FP rules, 0 chains

A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

**Aliases:** service configuration, configuration assessment, service hardening, protocol configuration, misconfigured service

## Technique

- **Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.**  
  `high_confidence` · score 0.8775 · disproved by: If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
  sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Fp Rule

- **A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.**  
  `high_confidence` · score 0.874 · disproved by: The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

## Known gaps

Not yet satisfied: `items`, `supported_items`, `fp_rules`, `chain`
