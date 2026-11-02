# LDAP as an Attack Surface

## Definition

Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.

- **CWE:** CWE-90
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["ldap", "ldap injection", "ldap filter injection", "null bind", "anonymous bind", "ldap signing", "channel binding"]

Canonical home for `ad_ldap`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.**

LDAP is the write and read path for nearly every AD object change, but the objects it exposes are numerous and many are readable by ordinary accounts, so the LDAP channel alone never tells you whether a change was legitimate. Before testing any LDAP-write hypothesis (attribute change, GPC link, msDS-* flag), confirm that object-level directory service auditing is enabled on the DC. If it was off at the time of the suspected change, the directory log holds no record of who changed what, and the only recoverable evidence is the GPC/GPT state in SYSVOL plus Group Policy History on endpoints. A tester who jumps straight to 'LDAP write succeeded' without the audit trail is asserting intent from a state change alone, which is the classic false-positive generator for this class.

*Disproof:* If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.

**Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.**

Absence of RSAT or admin tooling on an endpoint proves nothing, because the enumeration capability arrives as a stock Windows DLL that any domain-joined user can import. A hunter should therefore baseline directory read volume per workstation on the DC side rather than searching for tool presence on hosts, and should treat the AD Web Services and LDAP ports being reachable from a user segment as the condition that decides whether this prerequisite is met. The claim is falsified when a DC blocks or sharply limits ordinary-workstation LDAP directory reads, since then the reachability condition alone would not be sufficient.

*Disproof:* A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.**

The LDAP filter is not a value the server looks up — it is the predicate that decides which entries match, and RFC 4511 defines it as a full expression language with and/or/not and comparison matchers. That means the escaping requirements are structural, not cosmetic: an unescaped ')' closes the component the application intended to be a literal, and everything after it is parsed as further filter structure. The test is a differential one — submit a value containing ')' and '*' and compare the entry set returned against the set returned by the same query with those characters escaped. If the response changes shape rather than failing, the filter is being built by concatenation. Related but distinct: unsigned LDAP binds let a response be forged rather than a query be widened, and the two remediations (escaping, and authenticated+integrity-protected binds) do not substitute for each other.

*Disproof:* If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.**

The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass. Anonymous read is how every Active Directory domain is configured out of the box - the directory is built to answer authenticated and unauthenticated readers differently depending on ACL, and default ACLs permit broad read - so the observation reproduces the shipped configuration rather than deviating from it. What turns default-configuration read into an actual finding is the same connection reaching something stronger: write access to an object, a credentialed attribute such as unicodePwd or a replication attribute, or the configuration container. This rule rejects the anonymous bind as a bypass claim and redirects the check to those attributes, which is where the finding actually lives.

*Disproof:* The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.

**An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.**

The observation that triggers this false positive is a directory dump that returns a large, plausible Active Directory object graph from a host an operator assumed was just another LDAP listener on the network. Only a domain controller holds the AD database: a domain is a collection of networked computers that share a common database managed by a central authority, known as a domain controller. A host that answers 389 with AD-shaped content but has no rootDSE attributes naming the domain (domainDnsZones, domainController, configurationNamingContext) is therefore serving a copy, a restored backup, or a third-party directory that merely uses AD-like schemas. There is a second, related shape: ADWS (Active Directory Web Services) on TCP 9389 relays wrapped LDAP queries to the LDAP server located on the same domain controller, so enumeration can succeed against a DC while LDAP itself looks quiet on the wire. The benign explanation for both is that the tool picked a non-DC or used an indirect path. The distinguishing test is a second probe against the SAME host: read the rootDSE for domainDnsZones and domainController, then probe TCP 9389 for ADWS. A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory. Only when all three agree (graph present, domain naming attributes present, ADWS answering on the same host) is the observation a real DC exposure.

*Disproof:* A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/90.html>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/>
- **horizon3.ai** (writeup)
  - <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
- **proofpoint.com** (blog)
  - <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4511.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
