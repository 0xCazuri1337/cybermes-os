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

## 2026-10-04 00:43 — 64 diff lines
- items: 7 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -20,33 +20,48 @@
 
 ## Techniques (what to change)
 
-- When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts. _(unverified)_
+- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
+- When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.
+- Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
-- Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
+- Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "As a result, it is imperative that organizations implement exposure ma" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.
-  - **Disproof:** The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
-  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure) states the full boundary.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.
-  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.
-  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/service_enumeration_detail/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
```

## 2026-10-04 19:46 — 9 diff lines
- items: 7 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -65,6 +65,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/service_enumeration_detail/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 22 diff lines
- items: 7 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-16 · OWASP —
-> evidence: 7 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 7 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.
@@ -20,8 +20,8 @@
 
 ## Techniques (what to change)
 
-- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".
+- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Failure to utilize TLS or other strong transport for the login page allows an at”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 - When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
```

## 2026-10-29 14:12 — 50 diff lines
- items: 14 (supported 6), FP rules 2, chains 1, state mature

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-16 · OWASP —
-> evidence: 7 items, 6 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 14 items, 6 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.
 
@@ -20,15 +20,36 @@
 
 ## Techniques (what to change)
 
+- Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Alternatively, a single sign-on solution may authenticate the user and allow them to remai".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Failure to utilize TLS or other strong transport for the login page allows an at”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
+- Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrectly implemented error messages in the case of authentication functionality can be ".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example).  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Indeed, depending on the implementation, the processing time can be significantly differen".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Regarding the user enumeration itself, protection against brute-force attacks is also effe".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The counter of failed logins should be associated with the account itself, rather than the".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 - Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While UAF focuses on passwordless authentication, U2F allows the addition of a second fact".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this technique can prevent the user from having to type a password (thus protecting ".
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-31 06:41 — 55 diff lines
- items: 14 (supported 0), FP rules 0, chains 1, state researching
- still missing: supported_items, fp_rules

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-16 · OWASP —
-> evidence: 14 items, 6 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 14 items, 0 supported, 0 FP rules, 1 chains
+> maturity: **researching** — missing: supported_items, fp_rules
 
 A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.
 
@@ -23,7 +23,7 @@
 - Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Alternatively, a single sign-on solution may authenticate the user and allow them to remai".
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_
+- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Failure to utilize TLS or other strong transport for the login page allows an at”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 - Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -41,7 +41,7 @@
 - When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.  _(merged 1 duplicate row(s))_
+- Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -53,19 +53,19 @@
 
 ## False-positive rules (when to reject it)
 
-- A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.  _(merged 1 duplicate row(s))_
+- A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "As a result, it is imperative that organizations implement exposure ma" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure) states the full boundary.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 14 (supported 0), FP rules 0, chains 1, state researching
- still missing: supported_items, fp_rules

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -85,7 +85,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/infrastructure/service_enumeration_detail/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
+Full class document: `skills/network/infrastructure/service_enumeration_detail/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 14 (supported 0), FP rules 0, chains 1, state researching
- still missing: supported_items, fp_rules

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -5,7 +5,8 @@
 
 # Service-Specific Configuration Assessment — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
