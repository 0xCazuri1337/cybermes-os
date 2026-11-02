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
- **Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Alternatively, a single sign-on solution may authenticate the user and allow them to remai".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- **Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrectly implemented error messages in the case of authentication functionality can be ".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While UAF focuses on passwordless authentication, U2F allows the addition of a second fact".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- **A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint).**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A feature of more advanced applications is the ability to require different authentication".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **The application may return a different HTTP Error code depending on the authentication attempt response.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The application may return a different HTTP Error code depending on the authentication att".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- **Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- **Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Regarding the user enumeration itself, protection against brute-force attacks is also effe".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In return, the response time will be different for the same error, allowing the attacker t".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- **Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example).**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Indeed, depending on the implementation, the processing time can be significantly differen".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) .**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid requiring periodic password changes; instead, encourage users to pick strong passwor".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for authenticated pages after login enabl".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords .**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Screening passwords against blocklists helps prevent users from selecting passwords that a".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- **While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this technique can prevent the user from having to type a password (thus protecting ".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The counter of failed logins should be associated with the account itself, rather than the".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The objective is to prevent the creation of a discrepancy factor , allowing an attacker to".
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>

## Test

- **To decide this case, observe: Discard when the report rests on the tool being present and running: the joint advisory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's.**  
  `under_review` · score 0.893 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (exposed_rmm.fprule.presence_is_not_compromise) states the full boundary.
  sources: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a> · <https://netlas.io/blog/weaponized_rmm/>

## Fp Rule

- **A legitimately installed RMM agent on a host is not compromise; discard the finding when no unauthorised deployment was shown.**  
  `under_review` · score 0.874 · disproved by: Would be wrong where the installed agent version is one of the known-vulnerable builds and is internet-reachable, since that is an exposure in itself.
  sources: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a> · <https://netlas.io/blog/weaponized_rmm/>
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
