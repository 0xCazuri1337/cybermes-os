# Methodology — Active Directory Certificate Services Abuse

> Derived from 15 verified items. Regenerate with `python -m wks.methodgen --class adcs_abuse --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.

**References.** CWE-295

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.**

AD CS turns certificate issuance into an authentication path. If a template's extended key usage permits authentication and its subject alternative name is supplied by the enrolling principal, the issued certificate is a credential for whatever identity the requester named. Enrollment is often gated only by an 'Authenticated Users' or low-privilege group membership rather than by enrollment rights on the template, which means ordinary domain users qualify. The enumeration procedure is specific: list templates, check eku for client authentication, check who holds Enroll rights, and check whether the SAN comes from the request. All three conditions must hold; any one of them failing breaks the chain. The persisted consequence is what makes this class worth the hunt: a forged or over-privileged certificate survives a password reset for its validity period, so containment has to include revocation rather than relying on credential rotation.

- *Disproof:* If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1649/); [learn.microsoft.com](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/)

**The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.**

can be accessed through certsrv.msc. The key permissions for such attacks are: ManageCA and ManageCertificates. 
 ManageCA grants a principal the right to perform administrative actions on a Certificate Authority (CA). This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI. 
 The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement. While this permission alone cannot compromise the domain, it can be used to circumvent certain protections. 
 ESC8 – NTLM Relay to AD CS HTTP Endpoints 
 ESC8 leverages the web enrolment interface of Active Directory Certificate Services (AD CS). The web enrolment interface is an optional feature alongside AD CS which is often utilised. Due to authentication web enrolment endpoints are particular

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The ManageCertificates permission allows a principal to approve pending certific”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1649/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/)

**This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.**

r any other active entity within the domain. 
 ESC7 - Vulnerable Certificate Authority Access Control 
 A certificate authority has permissions that secure various CA actions, this can be accessed through certsrv.msc. The key permissions for such attacks are: ManageCA and ManageCertificates. 
 ManageCA grants a principal the right to perform administrative actions on a Certificate Authority (CA). This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI. 
 The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement. While this permission alone cannot compromise the domain, it can be used to circumvent certain protections. 
 ESC8 – NTLM Relay to AD CS HTTP Endpoints 
 ESC8 leverages the web enrolment interface of Active Directory Certificate Services (AD CS). The web enrolment in

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [rapid7.com](https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/)

**If enabled in the certificate template it can be easier to exploit weak mappings.**

Weak and strong mappings influence the authentication process. 
 Certificate attributes, defined in certificate templates, determine how the Subject Name and SAN fields are populated. Some attributes are mandatory, and missing attributes can prevent certificate enrolment. 
 ESC9 refers to a setting that stops the security extension szOID_NTDS_CA_SECURITY_EXT from being included in a certificate. If enabled in the certificate template it can be easier to exploit weak mappings. 
 If the certificate attribute msPKI-Enrollment-Flag contains the flag CT_FLAG_NO_SECURITY_EXTENSION, the szOID_NTDS_CA_SECURITY_EXT extension will not be embedded, meaning that even with StrongCertificateBindingEnforcement set to 1, the mapping will be performed similarly as a value of 0 in the registry key. 
 When the setting for StrongCertificateBindingEnforcement is set to the default setting

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If enabled in the certificate template it can be easier to exploit weak mappings”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1649/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/)

**Templates allowing user and machine authentication with weak configurations should be addressed.**

request certificates from sensitive templates. 
 Restrict Enrolment Permissions: Ensure that only authorized users or service accounts can request certificates using the Enrol and AutoEnrol permissions. 
 Review the CERTSVC_DCOM_ACCESS group to ensure that only legitimate users and computers have access to the certificate authority (CA).  
 
 Disable Unused or Vulnerable Certificate Templates 
 
 Templates allowing user and machine authentication with weak configurations should be addressed. 
 Use PowerShell or the Certification Authority MMC to disable templates no longer needed.  
 
 Implement Strong Key Protection 
 
 Use Hardware Security Modules (HSMs) for the storage of sensitive private keys, especially those belonging to CAs. 
 Ensure that certificates issued to users or services have strong key protection enabled, such as non-exportable keys or protected with Trusted Platfor

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Templates allowing user and machine authentication with weak configurations shou”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/adcs-attacks); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/)

**This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.**

s which can be achieved by allowing SAN request attributes to be provided (+EDITF_ATTRIBUTESUBJECTALTNAME2 flag set on CA). 
 The EDITF_ATTRIBUTESUBJECTALTNAME2 flag applies to the entire CA and therefore every single certificate template which allows less privileged user enrollment can be misused to issue certificates with a Domain / Enterprise Admin as an additional User Principal Name (UPN). 
 This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain. 
 ESC7 - Vulnerable Certificate Authority Access Control 
 A certificate authority has permissions that secure various CA actions, this can be accessed through certsrv.msc. The key permissions for such attacks are: ManageCA and ManageCertificates. 
 ManageCA grants a principal the right to perform administrative actions on a Certificate Authority (CA). This provides control over the EDITF_ATTRIBU

- *Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This allows an intruder to enroll through any template set up for domain authent”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/adcs-attacks); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/)

**Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.**

nterface of Active Directory Certificate Services (AD CS). The web enrolment interface is an optional feature alongside AD CS which is often utilised. Due to authentication web enrolment endpoints are particularly vulnerable to NTLM relay attacks. 
 A key vulnerability arises because not all of the AD CS web interfaces enforce HTTPS, which is essential for safeguarding against NTLM relay attacks. Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited. 
 ESC8 can be directed at any domain machine, including domain controllers, making these web enrolment endpoints attractive targets. NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack. 
 AD CA’s that are vulnerable to ESC8 meet the following conditions: 
 
 Web

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Furthermore, if the Certificate Authority (CA) has a published certificate templ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**Attackers exploit misconfigured certificate templates that grant excessive permissions.**

icates across an enterprise environment by specifying the key properties, permissions, and usage scenarios for certificates. 
 Additionally for query certificate templates or request certificates, a valid account is needed, often the misconfigurations rely on low privileged accounts being allowed to request certificates for high privileged ones. 
 ESC1 - Certificate Template Vulnerability Abuse 
 Attackers exploit misconfigured certificate templates that grant excessive permissions. These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges. 
 Templates vulnerable to ESC1 have the following configurations: 
 
 Client Authentication: True 
 Enabled: True 
 Enrolee Sup

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers exploit misconfigured certificate templates that grant excessive permi”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [rapid7.com](https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/)

**Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.**

s-DS-OIDToGroup-Link attribute links an issuance policy to a specific Active Directory group. If a certificate template is configured with the necessary enrolment rights for a particular user or computer, and the issuance policy for that template has an OID group link, the user or computer can request a certificate that effectively grants access to the resources as a member of the linked group. 
 Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions. However, it also has additional requirements, including:  
 
 The certificate template must have an issuance policy extension. 
 The issuance policy must link to a specific AD group through an OID group link.  
 
 The impact of ESC13 largely depends on which AD group the OID group link connects to. If the link is to a high-privilege group, such as the Domain Admin group, it could enable full priv

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Like other ESC vulnerabilities, ESC13 requires conditions such as client authent”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**If present the attacker needs to identify the Certificate Authority (CA) Server.**

ices (AD CS) typically follows a sequence of steps, targeting weaknesses in the ESC configuration and processes, focusing on compromising certificates for privilege escalation and lateral movement. Typical steps include: 
 
 Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services. If present the attacker needs to identify the Certificate Authority (CA) Server. 
 Enumerate and discover Vulnerable Certificate Templates: the attacker looks for misconfigurations in certificate templates, such as:
 
 Weak or non-restrictive security descriptors (ACLs). 
 Templates allowing Client Authentication or Enrollment for low-privileged users. 
 Templates that allow certificates to be issued without subject name constraints. 
 
 
 
 This activity can be done either u

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If present the attacker needs to identify the Certificate Authority (CA) Server.”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [rapid7.com](https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**These permissions permit any domain user to modify any property in the template, making the template vulnerable.**

ESC4 is possible when templates are misconfigured at the access control level. Should Access Control Entries (ACEs) allow unintended, or unprivileged Active Directory users to edit security settings in the template it can result in unintended users being granted one of the following template security permissions: 
 
 Owner 
 WriteOwnerPrincipals 
 WriteDaclPrincipals 
 WritePropertyPrincipals 
 
 These permissions permit any domain user to modify any property in the template, making the template vulnerable. 
 ESC5 - Vulnerable PKI Object Access Control 
 This is a post-exploitation attack that can only be performed once an attacker gains access as a local admin on the Certificate Authority (CA) server. The following must be met: 
   
 Certificate Authority Server as part of the Domain Local Admin access on the CA server Low Privileged Domain User 
 Once access is gained an attacker can exploit this

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These permissions permit any domain user to modify any property in the template,”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.**

d, meaning that even with StrongCertificateBindingEnforcement set to 1, the mapping will be performed similarly as a value of 0 in the registry key. 
 When the setting for StrongCertificateBindingEnforcement is set to the default setting of 1 and the CT_FLAG_NO_SECURITY_EXTENSION flag is applied, weaker certificate mappings are allowed. This becomes a problem when someone can modify an account. 
 Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access. 
 ESC10 - Weak certificate mapping 
 ESC10 is a variation of the same Domain compromise technique as ESC9. ESC9 uses an account that the current principal has GenericWrite permissions over to compromise any account in the Domain, including Domain Administrators. The main difference between ESC9 and ESC10 is that ESC9 is limited to a specific certificate template, whereas ESC10 has no restriction.

- *Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthori”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.**

ty Event ID 4688 (Process Creation with command-line auditing). This will capture suspicious PowerShell commands or the use of tools like Certutil and Certify. 
 Conclusions 
 AD CS is a critical component in managing and securing digital identities within an organization, enabling secure authentication, encryption, and digital signatures. Its complexity, however often leads to misconfigurations. Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security. Attackers can abuse poorly secured CA’s, weak certificate mapping, or misconfigured templates to escalate privileges or even achieve full domain compromise. 
 To mitigate these risks, it is vital for organizations to implement strong policies, enforce the use of security extensions, conduct regular auditing and protect sensitive data such as private keys and authentication credentials. Properly s

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Key vulnerabilities demonstrate that misconfigurations in certificate templates,”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [rapid7.com](https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A custom AD CS certificate template is only an abuse finding when its enrollee rights and flags diverge from the shipped standard templates, since custom templates are an intended feature.**

AD CS deliberately supports administrator-defined templates for specific business requirements alongside the shipped standards, and certificate enrolment is a routine operation in which the requester's identity is verified before issuance. So 'a custom template exists' is never the finding. The discriminating test is a diff: enumerate every template's enrollee rights and flags (ENROLLEE_SUPPLY_SUBJECT, ENROLLEE_NO_VALIDATION, PRIVATE_KEY_EXPORTABLE, ANY_APPLICATION_PURPOSE, and whether the template is published to Request Clients) and compare against what the shipped Web Server / Code Signing / User Authentication templates grant. Abuse shows up as a template that grants a low-priv or domain-user group an issuance right the standard templates withhold, or that disables requester validation. Absent that divergence, a custom template is configuration, not abuse.

- *Disproof:* If the template's enrollee rights and flags are identical to, or a strict subset of, the shipped standard templates and the issuing right maps to a documented business owner, then the template is legitimate customisation and the ADCS abuse claim does not hold.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/adcs-attacks); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A certificate template with Client Authentication enabled is not ESC1 unless enrollee-supplied subject, no manager approval and zero authorised signatures also hold.**

Discard when the only evidence is the Client Authentication EKU on a template: the ESC1 precondition list requires the template enabled, enrollee supplies subject, requires management approval false and authorised signatures required zero. It survives when all of those were confirmed and a certificate was issued with an arbitrary UPN.

- *Disproof:* Would be wrong for templates where an enrolment agent restriction or a published CRL effectively blocks use of the issued certificate.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
