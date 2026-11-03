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

## 2026-10-04 00:43 — 104 diff lines
- items: 21 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -20,64 +20,59 @@
 
 ## Techniques (what to change)
 
-- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
-- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
+- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
-- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
+- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
+  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
+- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
+- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
+- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
+- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
-- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
+- The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
+- There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
+- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
-- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
-- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
-- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
-- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
-- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.
-  - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
-  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
 ## False-positive rules (when to reject it)
 
-- One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.
+- One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.  _(merged 1 duplicate row(s))_
   - **Disproof:** Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.
   - Sources: <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.
+- Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.  _(merged 1 duplicate row(s))_
   - **Disproof:** Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
   - Sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 
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
 Full class document: `domains/network/active-directory/password_attacks/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 21 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -62,10 +62,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Rate-limit your attempts inside the authorized window and record what a single-account, low-and-slow check can and cannot conclude.
 
 ### What counts as proof
 
```

## 2026-10-04 02:42 — 46 diff lines
- items: 21 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -22,33 +22,37 @@
 
 - Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
   - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 21 (supported 3), FP rules 2, chains 1, state researching
- still missing: supported_items

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -77,6 +77,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/password_attacks/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 54 diff lines
- items: 21 (supported 10), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-521 · OWASP —
-> evidence: 21 items, 3 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: supported_items
+> evidence: 21 items, 10 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.
 
@@ -21,7 +21,7 @@
 ## Techniques (what to change)
 
 - Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Event 4625 adds to it: AS-REP Roasting can be executed before any authentication”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
@@ -30,7 +30,7 @@
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The badPasswordTime attribute complements these events: if several user objects ”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
@@ -41,17 +41,17 @@
 - The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
+- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The only approach proposed is to place a canary GPP password belonging to a user”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The variant applies to user objects configured not to require Kerberos pre-authe”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
+  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
 ## False-positive rules (when to reject it)
```

## 2026-10-04 21:50 — 11 diff lines
- items: 21 (supported 10), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -51,7 +51,7 @@
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
 ## False-positive rules (when to reject it)
```

## 2026-10-28 14:39 — 64 diff lines
- items: 12 (supported 9), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-521 · OWASP —
-> evidence: 21 items, 10 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 9 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.
@@ -20,39 +20,39 @@
 
 ## Techniques (what to change)
 
-- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Event 4625 adds to it: AS-REP Roasting can be executed before any authentication”) does not occur under a test that isolates that control.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
   - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.  _(merged 2 duplicate row(s))_ _(unverified)_
+- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.  _(merged 2 duplicate row(s))_ _(unverified)_
+- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The badPasswordTime attribute complements these events: if several user objects ”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.  _(merged 2 duplicate row(s))_ _(unverified)_
+- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 - The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 2 duplicate row(s))_
+- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The only approach proposed is to place a canary GPP password belonging to a user”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 2 duplicate row(s))_ _(unverified)_
+- The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The variant applies to user objects configured not to require Kerberos pre-authe”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 2 duplicate row(s))_ _(unverified)_
+- There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 2 duplicate row(s))_ _(unverified)_
+- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
+
+## Tests
+
+- Password spraying is detected by correlating failed authentications across many accounts that share a narrow time window and a common source, not by a single failed logon.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The spray finding fails when the failures involve only one account, when each account is tried with many different passwords, or when the failed events have no common source or narrow time window.
+  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-28 17:55 — 32 diff lines
- items: 12 (supported 5), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-521 · OWASP —
-> evidence: 12 items, 9 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.
@@ -35,16 +35,16 @@
 - The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 1 duplicate row(s))_
+- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The only approach proposed is to place a canary GPP password belonging to a user”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
-- The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 1 duplicate row(s))_
+- The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The variant applies to user objects configured not to require Kerberos pre-authe”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 1 duplicate row(s))_
+- There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
-- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 1 duplicate row(s))_
+- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 
```

## 2026-10-31 06:41 — 20 diff lines
- items: 12 (supported 4), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-521 · OWASP —
-> evidence: 12 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 4 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.
@@ -20,7 +20,7 @@
 
 ## Techniques (what to change)
 
-- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_
+- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
   - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
 - Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.  _(merged 1 duplicate row(s))_ _(unverified)_
```

## 2026-11-02 23:13 — 11 diff lines
- items: 12 (supported 4), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -76,7 +76,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/active-directory/password_attacks/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
+Full class document: `skills/network/active-directory/password_attacks/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 12 (supported 4), FP rules 2, chains 1, state mature

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -5,7 +5,8 @@
 
 # Password Attacks against Active Directory — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
