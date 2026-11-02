# LDAP as an Attack Surface

> surface: `ad` · CWE: CWE-90 · OWASP: —
> maturity: **researching** — 10 items, 5 supported, 0 FP rules, 1 chains

Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.

**Aliases:** ldap, ldap injection, ldap filter injection, null bind, anonymous bind, ldap signing, channel binding

## Prerequisite

- **Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.**  
  `high_confidence` · score 0.874 · disproved by: A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.
  sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.**  
  `high_confidence` · score 0.8355 · disproved by: If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Technique

- **An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.**  
  `high_confidence` · score 0.8805 · disproved by: If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
- **Anonymous LDAP bind on a domain controller can expose user accounts, groups, and directory structure without credentials.**  
  `high_confidence` · score 0.743 · disproved by: Anonymous bind is disabled and returns insufficientAccessRights.
  sources: <https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md> · <https://tryhackme.com/room/adbasicenumeration>
- **LDAP injection occurs when user input is concatenated into an LDAP filter, allowing an attacker to alter query logic and bypass authentication.**  
  `high_confidence` · score 0.743 · disproved by: Input is escaped per RFC 4515 or parameterized queries are used.
  sources: <https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md> · <https://www.kayssel.com/newsletter/issue-30/>
- **Nmap LDAP scripts enumerate naming contexts, users, and groups from a domain controller on ports 389 and 636.**  
  `under_review` · score 0.637 · disproved by: LDAP ports are filtered or the server requires signing and rejects the query.
  sources: <https://h3ll-ka1ser.gitbook.io/boot2root/active-directory-penetration-testing/enumeration/no-credentials/ldap-enumeration> · <https://tryhackme.com/room/adbasicenumeration>

## Test

- **To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.**  
  `under_review` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones) states the full boundary.
  sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>

## Fp Rule

- **An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.**  
  `under_review` · score 0.8465 · disproved by: A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.
  sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.**  
  `under_review` · score 0.844 · disproved by: The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.
  sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass.**  
  `under_review` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ldap.fp_rule.anonymous_ldap_read_is_default_ad_configuration) states the full boundary.
  sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>

## Known gaps

Not yet satisfied: `items`, `fp_rules`
