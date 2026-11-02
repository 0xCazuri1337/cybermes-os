# Methodology — LDAP as an Attack Surface

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class ad_ldap --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.

**References.** CWE-90

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.**

Absence of RSAT or admin tooling on an endpoint proves nothing, because the enumeration capability arrives as a stock Windows DLL that any domain-joined user can import. A hunter should therefore baseline directory read volume per workstation on the DC side rather than searching for tool presence on hosts, and should treat the AD Web Services and LDAP ports being reachable from a user segment as the condition that decides whether this prerequisite is met. The claim is falsified when a DC blocks or sharply limits ordinary-workstation LDAP directory reads, since then the reachability condition alone would not be sufficient.

- *Disproof:* A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.
- *Evidence:* high_confidence — [horizon3.ai](https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/); [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md)

**An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.**

LDAP is the write and read path for nearly every AD object change, but the objects it exposes are numerous and many are readable by ordinary accounts, so the LDAP channel alone never tells you whether a change was legitimate. Before testing any LDAP-write hypothesis (attribute change, GPC link, msDS-* flag), confirm that object-level directory service auditing is enabled on the DC. If it was off at the time of the suspected change, the directory log holds no record of who changed what, and the only recoverable evidence is the GPC/GPT state in SYSVOL plus Group Policy History on endpoints. A tester who jumps straight to 'LDAP write succeeded' without the audit trail is asserting intent from a state change alone, which is the classic false-positive generator for this class.

- *Disproof:* If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.**

The LDAP filter is not a value the server looks up — it is the predicate that decides which entries match, and RFC 4511 defines it as a full expression language with and/or/not and comparison matchers. That means the escaping requirements are structural, not cosmetic: an unescaped ')' closes the component the application intended to be a literal, and everything after it is parsed as further filter structure. The test is a differential one — submit a value containing ')' and '*' and compare the entry set returned against the set returned by the same query with those characters escaped. If the response changes shape rather than failing, the filter is being built by concatenation. Related but distinct: unsigned LDAP binds let a response be forged rather than a query be widened, and the two remediations (escaping, and authenticated+integrity-protected binds) do not substitute for each other.

- *Disproof:* If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/90.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.**

The observation that triggers this false positive is a directory dump that returns a large, plausible Active Directory object graph from a host an operator assumed was just another LDAP listener on the network. Only a domain controller holds the AD database: a domain is a collection of networked computers that share a common database managed by a central authority, known as a domain controller. A host that answers 389 with AD-shaped content but has no rootDSE attributes naming the domain (domainDnsZones, domainController, configurationNamingContext) is therefore serving a copy, a restored backup, or a third-party directory that merely uses AD-like schemas. There is a second, related shape: ADWS (Active Directory Web Services) on TCP 9389 relays wrapped LDAP queries to the LDAP server located on the same domain controller, so enumeration can succeed against a DC while LDAP itself looks quiet on the wire. The benign explanation for both is that the tool picked a non-DC or used an indirect path. The distinguishing test is a second probe against the SAME host: read the rootDSE for domainDnsZones and domainController, then probe TCP 9389 for ADWS. A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory. Only when all three agree (graph present, domain naming attributes present, ADWS answering on the same host) is the observation a real DC exposure.

- *Disproof:* A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/); [proofpoint.com](https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts)

**An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.**

The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass. Anonymous read is how every Active Directory domain is configured out of the box - the directory is built to answer authenticated and unauthenticated readers differently depending on ACL, and default ACLs permit broad read - so the observation reproduces the shipped configuration rather than deviating from it. What turns default-configuration read into an actual finding is the same connection reaching something stronger: write access to an object, a credentialed attribute such as unicodePwd or a replication attribute, or the configuration container. This rule rejects the anonymous bind as a bypass claim and redirects the check to those attributes, which is where the finding actually lives.

- *Disproof:* The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md); [redcanary.com](https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
