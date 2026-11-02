# Service-Specific Configuration Assessment

> surface: `net` · CWE: CWE-16 · OWASP: —
> maturity: **researching** — 14 items, 0 supported, 0 FP rules, 1 chains

A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

**Aliases:** service configuration, configuration assessment, service hardening, protocol configuration, misconfigured service

## Technique

- **Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.**  
  `under_review` · score 0.8775 · disproved by: If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
  sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.**  
  `under_review` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Alternatively, a single sign-on solution may authenticate the user and allow them to remai".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.**  
  `under_review` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrectly implemented error messages in the case of authentication functionality can be ".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.**  
  `under_review` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While UAF focuses on passwordless authentication, U2F allows the addition of a second fact".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale.**  
  `under_review` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Regarding the user enumeration itself, protection against brute-force attacks is also effe".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.**  
  `under_review` · score 0.7995 · disproved by: Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Failure to utilize TLS or other strong transport for the login page allows an at”) does not occur under a test that isolates that control.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example).**  
  `under_review` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Indeed, depending on the implementation, the processing time can be significantly differen".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.**  
  `under_review` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this technique can prevent the user from having to type a password (thus protecting ".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.**  
  `under_review` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The counter of failed logins should be associated with the account itself, rather than the".
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

## Fp Rule

- **A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.**  
  `under_review` · score 0.874 · disproved by: The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.869 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "As a result, it is imperative that organizations implement exposure ma" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.**  
  `under_review` · score 0.838 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure) states the full boundary.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.**  
  `under_review` · score 0.814 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Known gaps

Not yet satisfied: `supported_items`, `fp_rules`
