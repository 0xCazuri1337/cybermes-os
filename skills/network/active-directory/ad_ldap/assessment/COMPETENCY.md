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

**Anonymous LDAP bind on a domain controller can expose user accounts, groups, and directory structure without credentials.**

Some LDAP servers allow anonymous read queries. Test with ldapsearch -x -H ldap://DC -s base. If successful, enumerate users with (objectClass=person) and groups with (objectClass=group). Anonymous bind is a common misconfiguration that leaks the entire directory.

- *Disproof:* Anonymous bind is disabled and returns insufficientAccessRights.
- *Evidence:* high_confidence — [github.com](https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md); [tryhackme.com](https://tryhackme.com/room/adbasicenumeration)

**LDAP injection occurs when user input is concatenated into an LDAP filter, allowing an attacker to alter query logic and bypass authentication.**

Applications building LDAP filters from user input (e.g., (&(uid=INPUT)(password=INPUT))) are vulnerable. Injecting * or )(uid=*))(& can bypass filters. Special characters like *, (, ), |, & manipulate filter logic similarly to SQL injection but against directory queries.

- *Disproof:* Input is escaped per RFC 4515 or parameterized queries are used.
- *Evidence:* high_confidence — [github.com](https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md); [kayssel.com](https://www.kayssel.com/newsletter/issue-30/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, False-positive rejection, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
