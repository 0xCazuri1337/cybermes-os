# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 16 (supported 16), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 16 (supported 16), FP rules 2, chains 1, state mature

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -73,4 +73,4 @@
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 
 ---
-Full class document: `domains/network/infrastructure/service_enumeration_detail/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
+Full class document: `domains/network/infrastructure/service_enumeration_detail/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
```

## 2026-10-02 19:37 — 60 diff lines
- items: 5 (supported 3), FP rules 2, chains 1, state researching
- still missing: items, supported_items

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-16 · OWASP —
-> evidence: 16 items, 16 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 5 items, 3 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items, supported_items
 
 A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.
 
@@ -20,44 +20,11 @@
 
 ## Techniques (what to change)
 
-- As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".
-  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) .
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid requiring periodic password changes; instead, encourage users to pick strong passwor".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for authenticated pages after login enabl".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.
+- When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.
+- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".
-  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint).
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A feature of more advanced applications is the ability to require different authentication".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords .
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Screening passwords against blocklists helps prevent users from selecting passwords that a".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- The application may return a different HTTP Error code depending on the authentication attempt response.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The application may return a different HTTP Error code depending on the authentication att".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The objective is to prevent the creation of a discrepancy factor , allowing an attacker to".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- This section outlines when and how to trigger re-authentication to protect users and prevent unauthorized access.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This section outlines when and how to trigger re-authentication to protect users and preve".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In return, the response time will be different for the same error, allowing the attacker t".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 - Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.
   - **Disproof:** If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
```

## 2026-10-03 01:46 — 28 diff lines
- items: 7 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-16 · OWASP —
-> evidence: 5 items, 3 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items, supported_items
+> evidence: 7 items, 5 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.
 
@@ -39,5 +39,14 @@
   - **Disproof:** The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure) states the full boundary.
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+
 ---
 Full class document: `domains/network/infrastructure/service_enumeration_detail/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
```
