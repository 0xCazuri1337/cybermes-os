# Methodology — Pass-the-Hash and Ticket Replay

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class pass_the_hash --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

**References.** CWE-294

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery.**

Pass-the-hash removes the cracking step entirely. Where the protocol's proof is keyed on the NTLM hash, possessing the hash is possession of the credential, and it can be presented directly to any service accepting that hash. Pass-the-ticket is the same property one layer up: a valid Kerberos service ticket is already a bearer artifact for that service, so capturing and injecting it is a credential use, not a forgery. The practical consequence for hunting is that both techniques leave authentication SUCCESS events with no matching interactive logon — the tell is the absence of a preceding interactive session for that principal, not the presence of anything unusual in the logon itself. This also sets the boundary of the class: a protocol that requires a secret not derivable from the hash (smartcard/PIN, or a key the user holds) is outside it.

- *Disproof:* If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1550/003/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/294.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.**

Two distinct acts are routinely collapsed. Obtaining NT hashes is a credential-access result: in a real intrusion the operator replicates directory objects to impersonate the domain controller once an account with sufficient privileges is in hand, which yields password hashes for domain accounts. Using one is the pass-the-hash result. The validation that separates them is a replay: take the hash you recovered and attempt to authenticate with it against a service, then correlate the attempt in the target's own logon events. If the replay fails because the target enforces full signing or channel binding, or because the account's NTLM is disabled, the recovery finding stands on its own and the pass-the-hash finding must be dropped. Reporting the second as established from the first is the single most common inflation in this class.

- *Disproof:* If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## 3. False-positive rejection

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


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Credential-dumping on one host produces NT hashes that are directly reusable as NTLM credentials against every NTLM-accepting service in the reachable network, so the next link in the chain needs no password and no ticket issuance to gain an authenticated channel.**

Previous primitive hands over: a memory dump of the credential store on a single host, from which password hashes, user credentials, or Kerberos tickets are extracted. What the next link needs is a protocol that will accept a hash-derived response with no interactive logon, which SMB and WinRM both do. Observation that proves this segment: the same NT hash authenticates to a second host's administrative share or WinRM listener while a control hash from an unrelated account is rejected, so the authentication is attributable to the hash rather than to ambient network position. The handoff is a reusable credential, so the next link is remote execution on the second host, and the chain multiplies by one host per hash.

- *Disproof:* If the second host refuses NTLM outright (smarthosting, or channel binding with signing enforced), or if the dumped value is a Kerberos ticket rather than an NT hash and the target is domain-joined with Kerberos enforced, the handoff does not produce an authenticated channel and the chain stops at the first host.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1550/002/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing); [microsoft.com](https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
