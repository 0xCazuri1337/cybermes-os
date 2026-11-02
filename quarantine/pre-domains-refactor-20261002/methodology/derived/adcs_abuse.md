# Methodology — Active Directory Certificate Services Abuse

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class adcs_abuse --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A custom AD CS certificate template is only an abuse finding when its enrollee rights and flags diverge from the shipped standard templates, since custom templates are an intended feature.**

AD CS deliberately supports administrator-defined templates for specific business requirements alongside the shipped standards, and certificate enrolment is a routine operation in which the requester's identity is verified before issuance. So 'a custom template exists' is never the finding. The discriminating test is a diff: enumerate every template's enrollee rights and flags (ENROLLEE_SUPPLY_SUBJECT, ENROLLEE_NO_VALIDATION, PRIVATE_KEY_EXPORTABLE, ANY_APPLICATION_PURPOSE, and whether the template is published to Request Clients) and compare against what the shipped Web Server / Code Signing / User Authentication templates grant. Abuse shows up as a template that grants a low-priv or domain-user group an issuance right the standard templates withhold, or that disables requester validation. Absent that divergence, a custom template is configuration, not abuse.

- *Disproof:* If the template's enrollee rights and flags are identical to, or a strict subset of, the shipped standard templates and the issuing right maps to a documented business owner, then the template is legitimate customisation and the ADCS abuse claim does not hold.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/adcs-attacks); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**ESC8 exposure requires the AD CS web enrolment role to be installed and reachable over plain HTTP; a CA without it is not ESC8-vulnerable.**

Discard when the CA was found but the finding was written up from the CA existing alone: the Rapid7 advisory scopes the attack to domains running the Certificate Authority Web Enrollment or Certificate Enrollment Web Service, and the NCC guide ties the weakness to interfaces that do not enforce HTTPS. It survives when an unauthenticated or relayable HTTP enrolment endpoint answered on the CA.

- *Disproof:* Would be wrong where the enrolment role is installed but EPA plus Require SSL is correctly configured, because then the relay fails at authentication.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/); [rapid7.com](https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/)

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
