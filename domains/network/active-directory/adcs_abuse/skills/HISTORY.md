# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 25 (supported 25), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 25 (supported 25), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -103,4 +103,4 @@
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 
 ---
-Full class document: `domains/network/active-directory/adcs_abuse/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
+Full class document: `domains/network/active-directory/adcs_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
```

## 2026-10-02 19:37 — 100 diff lines
- items: 25 (supported 4), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-295 · OWASP —
-> evidence: 25 items, 25 supported, 2 FP rules, 1 chains
+> evidence: 25 items, 4 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.
@@ -20,67 +20,67 @@
 
 ## Techniques (what to change)
 
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.
+- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
-- Templates allowing user and machine authentication with weak configurations should be addressed.
+- Templates allowing user and machine authentication with weak configurations should be addressed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Templates allowing user and machine authentication with weak configurations should be addr".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- These permissions permit any domain user to modify any property in the template, making the template vulnerable.
+- These permissions permit any domain user to modify any property in the template, making the template vulnerable. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These permissions permit any domain user to modify any property in the template, making th".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.
+- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This allows an intruder to enroll through any template set up for domain authentication, s".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- This attack requires a victim account to authenticate to an attacker-controlled machine.
+- This attack requires a victim account to authenticate to an attacker-controlled machine. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This attack requires a victim account to authenticate to an attacker-controlled machine.".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.
+- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.
+- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin ".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.
+- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
-- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.
+- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Furthermore, if the Certificate Authority (CA) has a published certificate template that s".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates.
+- If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker gains remote command execution on the host operating system, they can explo".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Attackers exploit misconfigured certificate templates that grant excessive permissions.
+- Attackers exploit misconfigured certificate templates that grant excessive permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.
+- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If present the attacker needs to identify the Certificate Authority (CA) Server.
+- If present the attacker needs to identify the Certificate Authority (CA) Server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services.
+- Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.
+- With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite per".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.
+- NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.
+- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication an".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.
+- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissio".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges.
+- These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If enabled in the certificate template it can be easier to exploit weak mappings.
+- If enabled in the certificate template it can be easier to exploit weak mappings. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing.
+- If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an at".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.
```

## 2026-10-03 01:46 — 43 diff lines
- items: 25 (supported 4), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -52,19 +52,19 @@
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - Attackers exploit misconfigured certificate templates that grant excessive permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
-  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - If present the attacker needs to identify the Certificate Authority (CA) Server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
-  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite per".
-  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
@@ -76,7 +76,7 @@
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
-  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
 - If enabled in the certificate template it can be easier to exploit weak mappings. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
@@ -91,7 +91,7 @@
 
 - A custom AD CS certificate template is only an abuse finding when its enrollee rights and flags diverge from the shipped standard templates, since custom templates are an intended feature.
   - **Disproof:** If the template's enrollee rights and flags are identical to, or a strict subset of, the shipped standard templates and the issuing right maps to a documented business owner, then the template is legitimate customisation and the ADCS abuse claim does not hold.
-  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
 
 ## False-positive rules (when to reject it)
 
```
