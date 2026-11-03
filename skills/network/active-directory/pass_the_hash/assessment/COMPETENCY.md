# Methodology — Pass-the-Hash and Ticket Replay

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class pass_the_hash --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1550/003/); [learn.microsoft.com](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/)

**Pass-the-hash authenticates with a recovered NTLM hash directly as the password, so no plaintext is needed to open a session.**

In practice on HTB this shows up as: | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `responder -h`                                               | Used to display the usage instructions and various options available in `Responder` from a Linux-based host. |
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt` | Uses `hashcat` to crack `NTLMv2` (`-m`) hashes that were captured by responder and saved in a file (`frond_ntlmv2`). The cracking is done based on a specified wordlist. |
| `Import-Module .\Inveigh.ps1`                                | Using the `Import-Module` PowerShell cmd-let to import the Windows-based tool `Inveigh.ps1`. |
| `(Get-Command Invoke-Inveigh).Parameters`                    | Used to output many of the options & functionality available with `Invoke-Inveigh`. Peformed from a Windows-based host. |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/13. Active Directory Enumeration & Attacks.md (6753 words, classified network).

- *Disproof:* Refuted when the account is disabled, expired, or restricted so that NTLM authentication is refused, which stops the hash from being usable as a credential.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1550/002/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/294.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.**

Discard when the report ends at the dump: NTDS.dit and LSA secret extraction only produce hashes, and pass-the-hash additionally requires that hash to be presented to a second service for a session. It survives when the recovered hash authenticated to a remote host and produced an authenticated session there.

- *Disproof:* Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.
- *Evidence:* high_confidence — [rapid7.com](https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Credential-dumping on one host produces NT hashes that are directly reusable as NTLM credentials against every NTLM-accepting service in the reachable network, so the next link in the chain needs no password and no ticket issuance to gain an authenticated channel.**

Previous primitive hands over: a memory dump of the credential store on a single host, from which password hashes, user credentials, or Kerberos tickets are extracted. What the next link needs is a protocol that will accept a hash-derived response with no interactive logon, which SMB and WinRM both do. Observation that proves this segment: the same NT hash authenticates to a second host's administrative share or WinRM listener while a control hash from an unrelated account is rejected, so the authentication is attributable to the hash rather than to ambient network position. The handoff is a reusable credential, so the next link is remote execution on the second host, and the chain multiplies by one host per hash.

- *Disproof:* If the second host refuses NTLM outright (smarthosting, or channel binding with signing enforced), or if the dumped value is a Kerberos ticket rather than an NT hash and the target is domain-joined with Kerberos enforced, the handoff does not produce an authenticated channel and the chain stops at the first host.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1550/002/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing); [microsoft.com](https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
