---
name: adcs_abuse-hunting
description: Use when hunting Active Directory Certificate Services Abuse in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Active Directory Certificate Services Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-295 · OWASP —
> evidence: 25 items, 4 supported, 2 FP rules, 1 chains
> maturity: **mature**

A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.

**Also called:** ad cs, adcs, certificate template, certificate enrollment, cert template, esc1, esc4, esc6, enrollment agent


## Techniques (what to change)

- A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.  _(merged 1 duplicate row(s))_
  - **Disproof:** If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/>
- Attackers exploit misconfigured certificate templates that grant excessive permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers exploit misconfigured certificate templates that grant excessive permissions.".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- Furthermore, if the Certificate Authority (CA) has a published certificate template that supports client authentication and domain computer enrolment, which is very common, it can be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Furthermore, if the Certificate Authority (CA) has a published certificate template that s".
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environment by enumerating domain controllers and checking for certificate-related services.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Identify AD CS infrastructure: the attacker identifies if AD CS is present in the environm".
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- If an attacker gains remote command execution on the host operating system, they can exploit the YubiHSM CA’s private key to create and issue certificates.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker gains remote command execution on the host operating system, they can explo".
  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- If enabled in the certificate template it can be easier to exploit weak mappings.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If enabled in the certificate template it can be easier to exploit weak mappings.".
  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- If present the attacker needs to identify the Certificate Authority (CA) Server.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If present the attacker needs to identify the Certificate Authority (CA) Server.".
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an attacker can exploit this vulnerability to conduct NTLM relay attacks against the RPC service without requiring signing.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the CA server is not configured with the IF_ENFORCEENCRYPTICERTREQUEST attribute, an at".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissions, and registry settings can be exploited to compromise domain security.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Key vulnerabilities demonstrate that misconfigurations in certificate templates, permissio".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication and certificate enrolment permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Like other ESC vulnerabilities, ESC13 requires conditions such as client authentication an".
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin access.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfiguration of ESC9 permits an attacker the opportunity to obtain unauthorised admin ".
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- NTLM relay attacks often result in the attacker gaining privilege escalation by relaying the authentication to a service with higher privileges, allowing the attacker to further the attack.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "NTLM relay attacks often result in the attacker gaining privilege escalation by relaying t".
  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "PKI enables digital signatures, encryption, and authentication of electronic documents, em".
  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://academy.hackthebox.com/course/preview/adcs-attacks>
- Templates allowing user and machine authentication with weak configurations should be addressed.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Templates allowing user and machine authentication with weak configurations should be addr".
  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- The ManageCertificates permission allows a principal to approve pending certificate requests, bypassing any issuance requirement.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The ManageCertificates permission allows a principal to approve pending certificate reques".
  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- These permissions permit any domain user to modify any property in the template, making the template vulnerable.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These permissions permit any domain user to modify any property in the template, making th".
  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- These templates allow low privilege users to request certificates that impersonate high-privileged accounts, such as domain administrators leading to privilege escalation because attackers can request certificates that allow them to authenticate with elevated privileges.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These templates allow low privilege users to request certificates that impersonate high-pr".
  - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
- This allows an intruder to enroll through any template set up for domain authentication, specifically those open to unprivileged user enrollment, like the standard User template resulting in an attacker being able to authenticate as a domain administrator or any other active entity within the domain.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This allows an intruder to enroll through any template set up for domain authentication, s".
  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>
- This attack requires a victim account to authenticate to an attacker-controlled machine.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This attack requires a victim account to authenticate to an attacker-controlled machine.".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal with ManageCA rights to exploit ESC6 using the Enable-PolicyModuleFlag cmdlet in PSPKI.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This provides control over the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, enabling any principal".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
- With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite per".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/>

## Validation bar (how to prove it)

- A custom AD CS certificate template is only an abuse finding when its enrollee rights and flags diverge from the shipped standard templates, since custom templates are an intended feature.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the template's enrollee rights and flags are identical to, or a strict subset of, the shipped standard templates and the issuing right maps to a documented business owner, then the template is legitimate customisation and the ADCS abuse claim does not hold.
  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>

## False-positive rules (when to reject it)

- A certificate template with Client Authentication enabled is not ESC1 unless enrollee-supplied subject, no manager approval and zero authorised signatures also hold.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong for templates where an enrolment agent restriction or a published CRL effectively blocks use of the issued certificate.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.thehacker.recipes/ad/movement/adcs/certificate-templates>
- ESC8 exposure requires the AD CS web enrolment role to be installed and reachable over plain HTTP; a CA without it is not ESC8-vulnerable.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong where the enrolment role is installed but EPA plus Require SSL is correctly configured, because then the relay fails at authentication.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>


## Hunt procedure

1. Enumerate enrolled templates and their ACLs, then test only the ESC that the enrollment settings actually permit.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/active-directory/adcs_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
