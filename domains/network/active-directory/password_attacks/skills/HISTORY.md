# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 21 (supported 21), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 21 (supported 21), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -88,4 +88,4 @@
   - Sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 
 ---
-Full class document: `domains/network/active-directory/password_attacks/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
+Full class document: `domains/network/active-directory/password_attacks/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
```

## 2026-10-02 19:37 — 90 diff lines
- items: 21 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-521 · OWASP —
-> evidence: 21 items, 21 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 21 items, 3 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: supported_items
 
 Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.
 
@@ -20,58 +20,58 @@
 
 ## Techniques (what to change)
 
-- The variant applies to user objects configured not to require Kerberos pre-authentication.
+- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.
+- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- There is a single mitigating control: require Kerberos pre-authentication on all user objects.
+- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.
+- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.
+- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.
+- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.
+- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.
+- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.
+- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token.
+- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The variant applies to user objects configured not to require Kerberos pre-authentication.
+- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.
+- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- There is a single mitigating control: require Kerberos pre-authentication on all user objects.
+- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.
+- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.
+- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.
+- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.
+- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.
+- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.
```

## 2026-10-03 01:46 — 75 diff lines
- items: 21 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -22,61 +22,53 @@
 
 - The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
 - Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.
   - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
-  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
 ## False-positive rules (when to reject it)
 
```
