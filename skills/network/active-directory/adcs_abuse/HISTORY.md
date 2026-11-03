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

## 2026-10-04 00:43 — 157 diff lines
- items: 25 (supported 4), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -20,87 +20,99 @@
 
 ## Techniques (what to change)
 
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication. _(unverified)_
+- A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
+  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/>
+- Attackers exploit misconfigured certificate templates that grant excessive permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
+- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Furthermore, if the Certificate Authority (CA) has a published certificate template that s".
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker gains remote command execution on the host operating system, they can explo".
+  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- If enabled in the certificate template it can be easier to exploit weak mappings.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
+  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- If present the attacker needs to identify the Certificate Authority (CA) Server.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
+- If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an at".
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
+- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissio".
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
+- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication an".
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin ".
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
+  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
-- Templates allowing user and machine authentication with weak configurations should be addressed. _(unverified)_
+- Templates allowing user and machine authentication with weak configurations should be addressed.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Templates allowing user and machine authentication with weak configurations should be addr".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- These permissions permit any domain user to modify any property in the template, making the template vulnerable. _(unverified)_
+- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
+  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
+- These permissions permit any domain user to modify any property in the template, making the template vulnerable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These permissions permit any domain user to modify any property in the template, making th".
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain. _(unverified)_
+- These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
+  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
+- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This allows an intruder to enroll through any template set up for domain authentication, s".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- This attack requires a victim account to authenticate to an attacker-controlled machine. _(unverified)_
+- This attack requires a victim account to authenticate to an attacker-controlled machine.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This attack requires a victim account to authenticate to an attacker-controlled machine.".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI. _(unverified)_
+- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin ".
-  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
-  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
-- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Furthermore, if the Certificate Authority (CA) has a published certificate template that s".
-  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker gains remote command execution on the host operating system, they can explo".
-  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Attackers exploit misconfigured certificate templates that grant excessive permissions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
-  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If present the attacker needs to identify the Certificate Authority (CA) Server. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
-  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
-  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account. _(unverified)_
+- With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite per".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
-  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication an".
-  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissio".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
-  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
-- If enabled in the certificate template it can be easier to exploit weak mappings. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
-  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an at".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.
-  - **Disproof:** If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
... (truncated)
```

## 2026-10-04 00:50 — 14 diff lines
- items: 25 (supported 4), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -102,10 +102,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Enumerate enrolled templates and their ACLs, then test only the ESC that the enrollment settings actually permit.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 25 (supported 4), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -113,6 +113,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/adcs_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 102 diff lines
- items: 25 (supported 19), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-295 · OWASP —
-> evidence: 25 items, 4 supported, 2 FP rules, 1 chains
+> evidence: 25 items, 19 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.
@@ -23,11 +23,11 @@
 - A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/>
-- Attackers exploit misconfigured certificate templates that grant excessive permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
+- Attackers exploit misconfigured certificate templates that grant excessive permissions.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers exploit misconfigured certificate templates that grant excessive permi”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Furthermore, if the Certificate Authority (CA) has a published certificate template that s".
+- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Furthermore, if the Certificate Authority (CA) has a published certificate templ”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
@@ -35,50 +35,50 @@
 - If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker gains remote command execution on the host operating system, they can explo".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If enabled in the certificate template it can be easier to exploit weak mappings.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
+- If enabled in the certificate template it can be easier to exploit weak mappings.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If enabled in the certificate template it can be easier to exploit weak mappings”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- If present the attacker needs to identify the Certificate Authority (CA) Server.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
+- If present the attacker needs to identify the Certificate Authority (CA) Server.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If present the attacker needs to identify the Certificate Authority (CA) Server.”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an at".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissio".
+- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Key vulnerabilities demonstrate that misconfigurations in certificate templates,”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication an".
+- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Like other ESC vulnerabilities, ESC13 requires conditions such as client authent”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin ".
+- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthori”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
+- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“PKI enables digital signatures, encryption, and authentication of electronic doc”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
-- Templates allowing user and machine authentication with weak configurations should be addressed.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Templates allowing user and machine authentication with weak configurations should be addr".
+- Templates allowing user and machine authentication with weak configurations should be addressed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Templates allowing user and machine authentication with weak configurations shou”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
+- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The ManageCertificates permission allows a principal to approve pending certific”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- These permissions permit any domain user to modify any property in the template, making the template vulnerable.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These permissions permit any domain user to modify any property in the template, making th".
+- These permissions permit any domain user to modify any property in the template, making the template vulnerable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These permissions permit any domain user to modify any property in the template,”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
 - These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
-- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This allows an intruder to enroll through any template set up for domain authentication, s".
+- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This allows an intruder to enroll through any template set up for domain authent”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- This attack requires a victim account to authenticate to an attacker-controlled machine.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This attack requires a victim account to authenticate to an attacker-controlled machine.".
+- This attack requires a victim account to authenticate to an attacker-controlled machine.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This attack requires a victim account to authenticate to an attacker-controlled ”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
-- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal".
+- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite per".
```

## 2026-10-28 14:45 — 20 diff lines
- items: 24 (supported 18), FP rules 2, chains 1, state mature

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-295 · OWASP —
-> evidence: 25 items, 19 supported, 2 FP rules, 1 chains
+> evidence: 24 items, 18 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.
@@ -56,7 +56,7 @@
 - NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 2 duplicate row(s))_
+- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“PKI enables digital signatures, encryption, and authentication of electronic doc”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
 - Templates allowing user and machine authentication with weak configurations should be addressed.  _(merged 1 duplicate row(s))_
```

## 2026-10-31 06:41 — 40 diff lines
- items: 24 (supported 15), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-295 · OWASP —
-> evidence: 24 items, 18 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 24 items, 15 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.
 
@@ -56,7 +56,7 @@
 - NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 1 duplicate row(s))_
+- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“PKI enables digital signatures, encryption, and authentication of electronic doc”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
 - Templates allowing user and machine authentication with weak configurations should be addressed.  _(merged 1 duplicate row(s))_
@@ -74,7 +74,7 @@
 - This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This allows an intruder to enroll through any template set up for domain authent”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
-- This attack requires a victim account to authenticate to an attacker-controlled machine.  _(merged 1 duplicate row(s))_
+- This attack requires a victim account to authenticate to an attacker-controlled machine.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This attack requires a victim account to authenticate to an attacker-controlled ”) does not occur under a test that isolates that control.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 - This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.  _(merged 1 duplicate row(s))_
@@ -95,7 +95,7 @@
 - A certificate template with Client Authentication enabled is not ESC1 unless enrollee-supplied subject, no manager approval and zero authorised signatures also hold.  _(merged 1 duplicate row(s))_
   - **Disproof:** Would be wrong for templates where an enrolment agent restriction or a published CRL effectively blocks use of the issued certificate.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
-- ESC8 exposure requires the AD CS web enrolment role to be installed and reachable over plain HTTP; a CA without it is not ESC8-vulnerable.  _(merged 1 duplicate row(s))_
+- ESC8 exposure requires the AD CS web enrolment role to be installed and reachable over plain HTTP; a CA without it is not ESC8-vulnerable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Would be wrong where the enrolment role is installed but EPA plus Require SSL is correctly configured, because then the relay fails at authentication.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 24 (supported 15), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -112,7 +112,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/active-directory/adcs_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
+Full class document: `skills/network/active-directory/adcs_abuse/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 24 (supported 15), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -5,7 +5,8 @@
 
 # Active Directory Certificate Services Abuse — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
