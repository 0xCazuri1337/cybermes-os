# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 23 (supported 23), FP rules 4, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 23 (supported 23), FP rules 4, chains 1, state mature

```diff
--- exposed_rmm@current
+++ exposed_rmm@new
@@ -107,4 +107,4 @@
 - `supply_chain` (3 shared chain(s))
 
 ---
-Full class document: `domains/network/infrastructure/exposed_rmm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_rmm`
+Full class document: `domains/network/infrastructure/exposed_rmm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_rmm`
```

## 2026-10-02 19:37 — 83 diff lines
- items: 6 (supported 6), FP rules 4, chains 1, state researching
- still missing: items

```diff
--- exposed_rmm@current
+++ exposed_rmm@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 23 items, 23 supported, 4 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 6 items, 6 supported, 4 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.
 
@@ -26,63 +26,15 @@
 
 ## Techniques (what to change)
 
-- Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Alternatively, a single sign-on solution may authenticate the user and allow them to remai".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
-- Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example).
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Indeed, depending on the implementation, the processing time can be significantly differen".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) .
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid requiring periodic password changes; instead, encourage users to pick strong passwor".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for authenticated pages after login enabl".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/> · <https://netlas.io/blog/weaponized_rmm/>
-- Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrectly implemented error messages in the case of authentication functionality can be ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While UAF focuses on passwordless authentication, U2F allows the addition of a second fact".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
-- A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint).
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A feature of more advanced applications is the ability to require different authentication".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords .
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Screening passwords against blocklists helps prevent users from selecting passwords that a".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/> · <https://netlas.io/blog/weaponized_rmm/>
-- While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this technique can prevent the user from having to type a password (thus protecting ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- The application may return a different HTTP Error code depending on the authentication attempt response.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The application may return a different HTTP Error code depending on the authentication att".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
-- The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The counter of failed logins should be associated with the account itself, rather than the".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The objective is to prevent the creation of a discrepancy factor , allowing an attacker to".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
-- This section outlines when and how to trigger re-authentication to protect users and prevent unauthorized access.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This section outlines when and how to trigger re-authentication to protect users and preve".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
-- Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
-- Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Regarding the user enumeration itself, protection against brute-force attacks is also effe".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
-- In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In return, the response time will be different for the same error, allowing the attacker t".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
 - Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.
   - **Disproof:** If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.
   - Sources: <https://attack.mitre.org/techniques/T1219/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+
+## Tests
+
+- To decide this case, observe: isory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's. It survives when the agent was installed during the engagement window, or connects to attacker-controlled relay infrastructure.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (exposed_rmm.fprule.presence_is_not_compromise) states the full boundary.
+  - Sources: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a> · <https://netlas.io/blog/weaponized_rmm/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-03 01:46 — 11 diff lines
- items: 6 (supported 6), FP rules 4, chains 1, state researching
- still missing: items

```diff
--- exposed_rmm@current
+++ exposed_rmm@new
@@ -32,7 +32,7 @@
 
 ## Tests
 
-- To decide this case, observe: isory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's. It survives when the agent was installed during the engagement window, or connects to attacker-controlled relay infrastructure.
+- To decide this case, observe: Discard when the report rests on the tool being present and running: the joint advisory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (exposed_rmm.fprule.presence_is_not_compromise) states the full boundary.
   - Sources: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a> · <https://netlas.io/blog/weaponized_rmm/>
 
```
