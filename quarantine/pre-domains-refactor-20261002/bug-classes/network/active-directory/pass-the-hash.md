# Pass-the-Hash and Ticket Replay

## Definition

A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

- **CWE:** CWE-294
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["pass the hash", "pass-the-hash", "pth", "pass the ticket", "ticket replay", "overpass the hash"]

Canonical home for `pass_the_hash`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery.**

Pass-the-hash removes the cracking step entirely. Where the protocol's proof is keyed on the NTLM hash, possessing the hash is possession of the credential, and it can be presented directly to any service accepting that hash. Pass-the-ticket is the same property one layer up: a valid Kerberos service ticket is already a bearer artifact for that service, so capturing and injecting it is a credential use, not a forgery. The practical consequence for hunting is that both techniques leave authentication SUCCESS events with no matching interactive logon — the tell is the absence of a preceding interactive session for that principal, not the presence of anything unusual in the logon itself. This also sets the boundary of the class: a protocol that requires a secret not derivable from the hash (smartcard/PIN, or a key the user holds) is outside it.

*Disproof:* If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.

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

**A pass-the-hash attempt that returns access denied for a non-RID-500 local account is the protection WORKING, not a partial authentication bypass; do not file it as a finding unless LocalAccountTokenFilterPolicy is set to 0x1 or the hash authenticates as a RID-500 account, because token creation strips privileges from non-default administrator accounts by design.**

The observable that triggers this false positive is a pass-the-hash attempt returning access denied for a local account that is not RID 500, written up as a partial authentication bypass or a weakened hash policy. It is the opposite: token creation strips administrative privileges from non-default administrator accounts by design, so the refusal is the protection working exactly as intended. The single condition that inverts this is LocalAccountTokenFilterPolicy set to 0x1 on the target, which disables that stripping and lets a non-RID-500 hash authenticate with full local administrative rights. This rule rejects the denied hash as a finding and redirects the check to that one registry value, which turns a noise report into either a clean close or a real policy finding.

*Disproof:* The same non-RID-500 hash authenticates successfully against the target, which happens when LocalAccountTokenFilterPolicy is set to 0x1 on that host and means the protection that should have stripped the privileges is disabled.

**Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.**

Discard when the report ends at the dump: NTDS.dit and LSA secret extraction only produce hashes, and pass-the-hash additionally requires that hash to be presented to a second service for a session. It survives when the recovered hash authenticated to a remote host and produced an authenticated session there.

*Disproof:* Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.

**An NTLM type 3 network logon with no preceding interactive logon is normal for a service account and is not pass-the-hash evidence.**

Discard when the only signal is event 4624 logon type 3 with NTLM from a service account, because the source states legitimate connections normally have an interactive logon first except for service accounts. It survives when the same NTLM logon type follows from a named user account with no interactive session anywhere in the log, or when the hash was replayed to open a session.

*Disproof:* Would be wrong in a domain that forbids all NTLM, where any type 3 NTLM logon is anomalous regardless of account type.

## Validation

**A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.**

Two distinct acts are routinely collapsed. Obtaining NT hashes is a credential-access result: in a real intrusion the operator replicates directory objects to impersonate the domain controller once an account with sufficient privileges is in hand, which yields password hashes for domain accounts. Using one is the pass-the-hash result. The validation that separates them is a replay: take the hash you recovered and attempt to authenticate with it against a service, then correlate the attempt in the target's own logon events. If the replay fails because the target enforces full signing or channel binding, or because the account's NTLM is disabled, the recovery finding stands on its own and the pass-the-hash finding must be dropped. Reporting the second as established from the first is the single most common inflation in this class.

*Disproof:* If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1550/003/>
- **blog.marcfredericgomez.com** (writeup)
  - <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/294.html>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
  - <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>
- **zscaler.com** (writeup)
  - <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
