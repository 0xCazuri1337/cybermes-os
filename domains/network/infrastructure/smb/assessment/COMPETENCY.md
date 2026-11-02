# Methodology — SMB/CIFS Abuse

> Derived from 8 verified items. Regenerate with `python -m wks.methodgen --class smb --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.

**References.** CWE-732

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A server that still answers SMB_COM_NEGOTIATE with an SMBv1 dialect (NT LM 0.12) leaves a transaction path whose integrity check is a per-message bit in the SMB header rather than a property of the established session, and it is that path the pre-authentication primitives are written against, so a differential proving that SMB2 signing closes a relay path establishes nothing about this host.**

Read the dialect list before anything else. Send an SMB_COM_NEGOTIATE that offers only SMBv1 dialects (NT LM 0.12 and earlier), record the returned DialectIndex and the SecurityMode bits, then repeat the same probe offering only SMB 2.0.2 through 3.1.1 and compare the two answers. If the first probe is answered with a dialect index selecting NT LM 0.12, SMB1 is present on this host. In the SMB1 header the integrity check is the SECURITY_SIGNATURE bit of the Flags2 field on each individual message, and a bit that is not set means the message was not integrity checked, so the inbound/outbound signing requirements that decide whether an SMB2 session is signed do not cover this path at all. The dialect index alone is a lead; the second half of the test is what shows whether anything is exposed. Follow the dialect selection with a minimal SMBv1 transaction and record the STATUS the server returns. STATUS_NOT_IMPLEMENTED, or a connection the server drops during the transaction, closes the path; a STATUS showing the request was parsed and executed is what is worth chasing. Record the raw NEGOTIATE response bytes next to the transaction STATUS, because the dialect index is the only field that distinguishes a host that still speaks SMBv1 from a modern host that merely listens on tcp/445.

- *Disproof:* Wrong when the NEGOTIATE response contains no SMBv1 dialect at all - DialectIndex 0xFFFF, or a dialect list holding only SMB 2.0.2 through 3.1.1 - and the same host terminates a connection that offers only NT LM 0.12: the SMB1 transaction path does not exist there, no pre-authentication primitive can reach it, and an SMB2 signing differential is the only relevant test. The claim is also not a statement of exploitability: a host that returns the SMBv1 dialect and then refuses the transaction primitive outright (patched for MS17-010) has the surface but no working primitive on it, which makes the dialect a lead to record rather than a finding to file.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/draft-leach-cifs-v1-spec-01); [learn.microsoft.com](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.**

Because SMB carries file access, remote procedure calls and remote execution over one authenticated session, a share write is a staging step rather than an endpoint — the file lands and something else runs it. ATT&CK names the executions that ride the same authenticated SMB/RPC session: scheduled task, service execution and WMI. That changes the priority order for hunting: a host that writes a file to a remote administrative share and a host that then connects to create a service on that target are one incident, not two. NetBIOS is the naming and transport layer underneath, which is why the original NetBIOS-over-TCP specification still matters for understanding why a name resolution answer can direct a client to the adversary's listener. The practical control is signing: where SMB signing is not required, an intercepted or coerced authentication is reusable; where it is required, the relay and coercion variants close even though the file transfer does not.

- *Disproof:* If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/002/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1002.html)

**An SMB client that is granted a write-caching opportunistic lock reads and writes the file out of its own cache under the file id the server assigned, so a server that hands the same file id to two different files collapses both onto one client cache key and the client returns the other file's data, meaning the bytes a victim reads over SMB are not necessarily the bytes sitting on the share.**

Reproduce the collision the way it was found: put two files of clearly different sizes on one share, open both over SMB from a Windows client, and record the length each open reports back. A length that belongs to the other file is the signal. Then separate a cache-key collision from a transfer error by asking the server for the same two files locally and comparing the file ids it hands out - on Samba, samba-tool ntacl getdosinfo shows the itime that becomes the id; on Windows, fsutil file queryfileid shows the id itself - and check whether the two values are equal. The mechanism is the read and write cache the client keeps while it holds the lock: the client asks for an opportunistic lock when it opens the file, the server grants it whenever other factors make it possible, and while the lock stands the client works on its local copy and synchronises only when the server breaks the lock. A duplicate file id is therefore all that is needed to make one cache key serve two distinct files. Record whether write caching was granted at all, because the discrepancy cannot arise on a share that refuses oplocks or breaks the lock immediately, and record the oplock break or lease break that ends it, because that is the moment the poisoned cache is discarded and the true content re-read.

- *Disproof:* Wrong when the server never grants a write-caching opportunistic lock - a share configured with oplocks disabled, or one that breaks the lock on every conflicting open - because each client read then goes back to the server for the bytes and no cache key can serve another file's data, so the length the client reports always tracks the file on the share. Also wrong where the two paths really are issued distinct file ids and the client-side length always matches the server-side file: the differential to record is the two file ids against the two reported lengths, and when they agree the claim does not hold.
- *Evidence:* high_confidence — [bugzilla.samba.org](https://bugzilla.samba.org/show_bug.cgi?id=14928); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks); [web.mit.edu](https://web.mit.edu/samba/swat/help/Samba3-HOWTO/locking.html)

**Anonymous or guest access to an SMB share, and the enumeration that reveals it, is the usual route to credentials or a file drop on a Windows target.**

In practice on HTB this shows up as: | `crackmapexec smb <FQDN/IP> --shares -u '' -p ''`                              | Enumerating SMB shares using null session authentication.  |
| `enum4linux-ng <FQDN/IP> -A`                                                   | **SMB enumeration using enum4linux-ng in aggressive mode** |
| `smb: \> tarmode`<br>`smb: \> recurse`<br>`smb: \> prompt`<br>`smb: \> mget *` | Download all files in smbclient                            |
| `netexec smb 10.10.11.35 -u 'guest' -p '' --rid-brute`                         | RID Brute (users)                                          |
Mount a SMB server in Linux: `sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance`

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Footprinting Services.md (2508 words, classified network).

- *Disproof:* Refuted when the share requires authentication and rejects guest/anonymous sessions, and no share permits a write, so the share yields neither credentials nor a file drop.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/002/); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Footprinting%20Services.md)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A relay finding is bounded by the negotiated signing state, so the validation that separates a real relay path from a non-finding is a differential test of the same request with and without a valid signature, not the mere presence of an SMB listener.**

What the primitive gives you: a candidate relay path. Microsoft's signing documentation states that Windows and Windows Server can require outbound signing only, inbound signing only, both, or neither, and that signature mismatches alert users to possible foul play, helping protect deployments against relay and spoofing attacks. Tenable's force-authentication writeup supplies the other half: the credential the first service leaked is only exploitable where it can be replayed, which is precisely what signing state determines. The precondition the next link needs is therefore a specific, measured combination of outbound and inbound policy on the two hosts in the path. Observation that proves the segment: a session with a correct signature succeeds and the same session with an invalid or absent signature is rejected, confirming signing is enforced; the inverse result confirms the path is live.

- *Disproof:* If the server accepts unsigned or wrongly-signed SMB sessions on the relevant share, the differential shows no rejection and the relay ceiling is not established by configuration alone; conversely if the server enforces signing on both ends, the relay link is closed and the finding does not hold regardless of listener exposure.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing); [tenable.com](https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.**

Discard when a scan reported Message signing enabled but not required and nothing was relayed: the BloodHound edge only covers victims with admin access to an unsigned target, and Rapid7 recorded an engagement where signing being not required could not be leveraged at all. It survives when a coerced authentication was actually relayed and authenticated on the second host.

- *Disproof:* Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.
- *Evidence:* high_confidence — [rapid7.com](https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/); [specterops.io](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)

**SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.**

Two shapes get flagged wrongly. First, netsh interface portproxy is a supported Windows redirection facility: a listen port on one interface forwarding to a different address and port, in the observed case a web port forwarded to 445. That is a documented administrative feature and it produces exactly the traffic shape an assessor reads as an SMB pivot. Second, enumeration and exploitation toolkits deliberately live off the land by abusing built-in AD protocols such as SMB, WMI and WinRM, so an SMB session from a management workstation is often the toolkit doing its job rather than an intruder. Before calling either case lateral movement, establish who configured the redirection, from what management context it was created, and whether the SMB peer is in the tool's documented target list.

- *Disproof:* If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy); [securelist.com](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A server that initiates an outbound SMB connect to an attacker-chosen host will answer that host's challenge with its own NTLM credentials, so a force-authentication primitive converts an unauthenticated connection into a relayable credential without the attacker ever holding a password.**

Previous primitive hands over: the ability to make the target process open an SMB session to a host the attacker controls, which Tenable demonstrated as a real SMB force-authentication flaw where the server's own NTLM credentials were leaked to a remote server. Precondition the NEXT link needs: a second service that accepts NTLM authentication and does not enforce signing or channel binding, because the credential the first service leaked is only useful where it can be replayed. Observation that proves this segment: the attacker-controlled listener receives a Type 2 challenge followed by a Type 3 message carrying an NTLM response for the server's account, and that response is then accepted by a different service. The handoff is a captured NTLM challenge-response pair, which is either relayed live or cracked offline.

- *Disproof:* If SMB signing is mandatory on the first connection, or the target refuses outbound SMB to untrusted peers, or channel binding pins the second service to a TLS channel the attacker does not hold, no NTLM response is emitted or accepted and the relay link has nothing to work with.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening); [tenable.com](https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
