<!-- GENERATED from db/wks.db — do not edit -->
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

## Known gaps

Not yet satisfied: `items`, `fp_rules`
