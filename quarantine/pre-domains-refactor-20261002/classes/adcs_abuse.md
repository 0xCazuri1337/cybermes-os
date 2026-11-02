# Active Directory Certificate Services Abuse

> surface: `ad` · CWE: CWE-295 · OWASP: —
> maturity: **researching** — 4 items, 4 supported, 2 FP rules, 0 chains

A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.

**Aliases:** ad cs, adcs, certificate template, certificate enrollment, cert template, esc1, esc4, esc6, enrollment agent

## Technique

- **A certificate template that authenticates and can be enrolled by a low-privilege principal issues a credential whose subject name is attacker-chosen, so enrollment becomes domain authentication with no password involved.**  
  `high_confidence` · score 0.8775 · disproved by: If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
  sources: <https://attack.mitre.org/techniques/T1649/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/>

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

## Known gaps

Not yet satisfied: `items`, `chain`
