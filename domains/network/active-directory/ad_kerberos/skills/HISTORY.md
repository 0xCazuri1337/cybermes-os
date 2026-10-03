# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 4, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 4, chains 1, state mature

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -76,4 +76,4 @@
   - Rule: a Kerberoasting threshold that counts system SPNs or raw response packets is invalid; require a per-client count of unique non-system sname values before calling the fan-out an attack
 
 ---
-Full class document: `domains/network/active-directory/ad_kerberos/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_kerberos`
+Full class document: `domains/network/active-directory/ad_kerberos/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_kerberos`
```

## 2026-10-02 19:37 — 38 diff lines
- items: 14 (supported 11), FP rules 4, chains 1, state mature

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-287 · OWASP —
-> evidence: 13 items, 13 supported, 4 FP rules, 1 chains
+> evidence: 14 items, 11 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.
@@ -26,13 +26,13 @@
 
 ## Techniques (what to change)
 
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
 - A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.
@@ -65,6 +65,9 @@
 - An account flagged Do not require Kerberos preauthentication can be turned into a password hash by any domain user, because the AS-REP returned in place of a pre-authentication exchange is encrypted with that user's NTLM hash.
   - **Disproof:** Refuted if preauthentication is enforced for every user in the domain, or if all qualifying accounts hold passwords of high enough entropy that offline cracking fails; the roast still succeeds but yields nothing.
   - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
+- Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack them offline without triggering account lockout.
+  - **Disproof:** If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.
+  - Sources: <https://capec.mitre.org/data/definitions/191.html> · <https://capec.mitre.org/data/definitions/497.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md>
 - Kerberoasting is available to any domain user because the service ticket returned for a service principal name carries a portion encrypted with the service account's NTLM hash, which the attacker cracks offline without ever touching that account's password.
   - **Disproof:** Refuted if every service principal name is mapped to an account whose password is a random value of high entropy, or if the domain has disabled RC4 so tickets are AES-encrypted and offline cracking is impractical.
   - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
```

## 2026-10-03 01:46 — 38 diff lines
- items: 15 (supported 12), FP rules 4, chains 1, state mature

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-287 · OWASP —
-> evidence: 14 items, 11 supported, 4 FP rules, 1 chains
+> evidence: 15 items, 12 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.
@@ -28,19 +28,22 @@
 
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
+  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
 - This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
+  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
 - A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.
   - **Disproof:** If enumeration returns no accounts with preauthentication disabled, or an AS-REQ without an encrypted timestamp is rejected with KDC_ERR_PREAUTH_REQUIRED for every account tested, then no AS-REP material exists and the attack has no precondition.
   - Sources: <https://attack.mitre.org/techniques/T1558/004/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
 - A Kerberos service ticket whose SPN is issued to an account with no interactive login (a service principal) is an offline password-cracking oracle when the KDC still protects it with RC4, because the ticket's encrypted part is keyed on the account password hash.
   - **Disproof:** If the KDC refuses to issue service tickets to requesting users' RC4 (etype 23 is globally disabled), or every crackable ticket offline fails to recover the account password, then this class is not exploitable in this environment and the finding is a false positive.
-  - Sources: <https://attack.mitre.org/techniques/T1558/003/> · <https://cwe.mitre.org/data/definitions/294.html> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
+  - Sources: <https://attack.mitre.org/techniques/T1558/003/> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
+- Kerberoasting targets service tickets for accounts with a pre-authentication setting that permits it, and the returned ticket is cracked offline for the account password.
+  - **Disproof:** Refuted when no account has a non-empty SPN or the accounts that do are configured not to require pre-authentication, in which case no roastable ticket is obtainable.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
 - Possession of the KRBTGT account password hash is sufficient to forge arbitrary Kerberos ticket-granting tickets for any principal in the forest, because KRBTGT is the key that signs and encrypts every TGT in that domain.
   - **Disproof:** If KRBTGT cannot be dumped (credential protection intact, PAW/Protected Users enforced) or a ticket minted from the hash is rejected by a domain controller, then no forged TGT is usable and the class does not apply here.
   - Sources: <https://attack.mitre.org/techniques/T1558/001/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
```
