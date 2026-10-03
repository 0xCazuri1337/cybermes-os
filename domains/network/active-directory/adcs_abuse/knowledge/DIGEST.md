# Active Directory Certificate Services Abuse

> surface: `ad` · CWE: CWE-295 · OWASP: —
> maturity: **mature** — 25 items, 25 supported, 2 FP rules, 1 chains

A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.

**Aliases:** ad cs, adcs, certificate template, certificate enrollment, cert template, esc1, esc4, esc6, enrollment agent

## Technique

- **A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.**  
  `high_confidence` · score 0.8775 · disproved by: If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/>
- **The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges.**  
  `high_confidence` · score 0.8455 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker gains remote command execution on the host operating system, they can explo".
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **This attack requires a victim account to authenticate to an attacker-controlled machine.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This attack requires a victim account to authenticate to an attacker-controlled machine.".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- **This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- **NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
  sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Attackers exploit misconfigured certificate templates that grant excessive permissions.**  
  `high_confidence` · score 0.8155 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- **If enabled in the certificate template it can be easier to exploit weak mappings.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Templates allowing user and machine authentication with weak configurations should be addressed.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Templates allowing user and machine authentication with weak configurations should be addr".
  sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This allows an intruder to enroll through any template set up for domain authentication, s".
  sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Furthermore, if the Certificate Authority (CA) has a published certificate template that s".
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite per".
  sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication an".
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an at".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- **If present the attacker needs to identify the Certificate Authority (CA) Server.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
  sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
- **PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
- **These permissions permit any domain user to modify any property in the template, making the template vulnerable.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These permissions permit any domain user to modify any property in the template, making th".
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin ".
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
  sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- **Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissio".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>

## Validation

- **A custom AD CS certificate template is only an abuse finding when its enrollee rights and flags diverge from the shipped standard templates, since custom templates are an intended feature.**  
  `high_confidence` · score 0.863 · disproved by: If the template's enrollee rights and flags are identical to, or a strict subset of, the shipped standard templates and the issuing right maps to a documented business owner, then the template is legitimate customisation and the ADCS abuse claim does not hold.
  sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Fp Rule

- **ESC8 exposure requires the AD CS web enrolment role to be installed and reachable over plain HTTP; a CA without it is not ESC8-vulnerable.**  
  `high_confidence` · score 0.8715 · disproved by: Would be wrong where the enrolment role is installed but EPA plus Require SSL is correctly configured, because then the relay fails at authentication.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- **A certificate template with Client Authentication enabled is not ESC1 unless enrollee-supplied subject, no manager approval and zero authorised signatures also hold.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong for templates where an enrolment agent restriction or a published CRL effectively blocks use of the issued certificate.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
