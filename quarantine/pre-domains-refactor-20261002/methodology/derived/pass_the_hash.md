# Methodology — Pass-the-Hash and Ticket Replay

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class pass_the_hash --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

**References.** CWE-294

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.**

Two distinct acts are routinely collapsed. Obtaining NT hashes is a credential-access result: in a real intrusion the operator replicates directory objects to impersonate the domain controller once an account with sufficient privileges is in hand, which yields password hashes for domain accounts. Using one is the pass-the-hash result. The validation that separates them is a replay: take the hash you recovered and attempt to authenticate with it against a service, then correlate the attempt in the target's own logon events. If the replay fails because the target enforces full signing or channel binding, or because the account's NTLM is disabled, the recovery finding stands on its own and the pass-the-hash finding must be dropped. Reporting the second as established from the first is the single most common inflation in this class.

- *Disproof:* If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An NTLM type 3 network logon with no preceding interactive logon is normal for a service account and is not pass-the-hash evidence.**

Discard when the only signal is event 4624 logon type 3 with NTLM from a service account, because the source states legitimate connections normally have an interactive logon first except for service accounts. It survives when the same NTLM logon type follows from a named user account with no interactive session anywhere in the log, or when the hash was replayed to open a session.

- *Disproof:* Would be wrong in a domain that forbids all NTLM, where any type 3 NTLM logon is anomalous regardless of account type.
- *Evidence:* high_confidence — [blog.marcfredericgomez.com](https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/)

**A pass-the-hash attempt that returns access denied for a non-RID-500 local account is the protection WORKING, not a partial authentication bypass; do not file it as a finding unless LocalAccountTokenFilterPolicy is set to 0x1 or the hash authenticates as a RID-500 account, because token creation strips privileges from non-default administrator accounts by design.**

The observable that triggers this false positive is a pass-the-hash attempt returning access denied for a local account that is not RID 500, written up as a partial authentication bypass or a weakened hash policy. It is the opposite: token creation strips administrative privileges from non-default administrator accounts by design, so the refusal is the protection working exactly as intended. The single condition that inverts this is LocalAccountTokenFilterPolicy set to 0x1 on the target, which disables that stripping and lets a non-RID-500 hash authenticate with full local administrative rights. This rule rejects the denied hash as a finding and redirects the check to that one registry value, which turns a noise report into either a clean close or a real policy finding.

- *Disproof:* The same non-RID-500 hash authenticates successfully against the target, which happens when LocalAccountTokenFilterPolicy is set to 0x1 on that host and means the protection that should have stripped the privileges is disabled.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md); [redcanary.com](https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/)

**Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.**

Discard when the report ends at the dump: NTDS.dit and LSA secret extraction only produce hashes, and pass-the-hash additionally requires that hash to be presented to a second service for a session. It survives when the recovered hash authenticated to a remote host and produced an authenticated session there.

- *Disproof:* Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.
- *Evidence:* high_confidence — [rapid7.com](https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**The NT hash of a machine account is a first-class reusable credential, so a compromised workstation yields lateral movement to whatever the machine account is a member of without ever recovering a user password.**

Machine accounts are routinely dismissed because no human chose their secret, yet they are ordinary domain principals with the same NTLM hash behaviour and, critically, group membership. The lab makes the equivalence explicit: computer/machine accounts are essentially the same as user accounts and can be as dangerous if misconfigured, and their NTLM password hashes can be used in pass the hash attacks to gain additional privileges depending on which groups the machine is a member of, ideally administrators or domain administrators. The credential-theft half is standard: the lab extracts a machine accounts NT hash after gaining admin on the host and then passes it directly to escalate to domain admin. Combined with the offline-crack evidence that any recoverable NT hash is immediately usable as a credential, a single administrative foothold on one host becomes whatever authority that host's machine account was granted, which in poorly governed estates is domain-wide.

- *Disproof:* Refuted if machine accounts are not members of any privileged group and network logons are enforced to reject their hashes, or if the host was not compromised to the point where its hash was readable.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md); [zscaler.com](https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Test sequence, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
