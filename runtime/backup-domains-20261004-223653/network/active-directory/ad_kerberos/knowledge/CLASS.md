# Kerberos Authentication Weaknesses

## Definition

Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.

- **CWE:** CWE-287
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["kerberoasting", "kerberoast", "asrep roasting", "as-rep roasting", "asreproasting", "golden ticket", "silver ticket", "spn", "service principal name", "ticket forgery", "tgs request", "service ticket", "krbtgt"]

Canonical home for `ad_kerberos`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A single host receiving TGS-REP responses for numerous unique SPNs inside a short window is an early observable for Kerberoasting but is identical to legitimate service-ticket traffic.**

The fan-out shape to alert on is one client name, many unique service names, one time window, all non-system service accounts. Kerberoasting produces exactly this because a single TGT holder requests TGS tickets for many SPNs in sequence. What makes it only a signal: the TGS ticket requests an attacker makes are byte-for-byte the same as ordinary legitimate requests, and every domain generates a high volume of Kerberos traffic, so there is no signature to match on. A management server, a monitoring agent, or an SAP/mail client that legitimately services many SPNs produces the same fan-out. Treat the shape as the hypothesis generator and go looking for which service accounts were in the fan-out and whether they are non-system accounts whose password age makes offline cracking plausible.

*Disproof:* If the unique SPNs in the window resolve to a single known management or monitoring principal that is documented to service that SPN set on a schedule, then the fan-out is the agent's normal behaviour and the Kerberoasting hypothesis for that host is invalidated.

## Exploitation

**This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**

isn't likely to go anywhere any time soon since Microsoft is improving and blending implementations with Azure AD. Another interesting stat to consider is that just in the last two years, Microsoft has had over 2000 reported vulnerabilities tied to a CVE . AD's many services and main purpose of making information easy to find and access make it a bit of a behemoth to manage and correctly harden. This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these misconfigurations and ease of access with common user and OS vulnerabilities, and you have a perfect storm for an attacker to take advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take advantage of their existence. We will practice enumerating AD utilizing native tools and languages such as Sysintern

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".

**This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.**

n compromise and looking for every possible path to Domain Admin level access within the testing period. Many open-source tools are available to facilitate enumerating and attacking Active Directory. To be most effective, we must understand how to perform as much of this enumeration manually as possible. More importantly, we need to understand the "why" behind certain flaws and misconfigurations. This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. 
 We need to be comfortable enumerating and attacking AD from both Windows and Linux, with a limited toolset or built-in Windows tools, also known as " living off the land ." It is common to run into situations where our tools fail, are being blocked, or we are conducting an assessment where the client has us work from a managed workstation or VDI instance instead of the customized Linux or Windo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".

**SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**

ra and Medusa, and the importance of strong password practices. It covers various attack scenarios, such as targeting SSH, FTP, and web login forms. 
 
 
 
 SQL Injection Fundamentals 
 
 
 Medium 
 
 
 17 Sections 
 
 Reward: +10 
 
 Databases are an important part of web application infrastructure and SQL (Structured Query Language) to store, retrieve, and manipulate information stored in them. SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. 
 
 
 
 SQLMap Essentials 
 
 
 Easy 
 
 
 11 Sections 
 
 Reward: +20 
 
 The SQLMap Essentials module will teach you the basics of using SQLMap to discover various types of SQL Injection vulnerabilities, all the way to the advanced enumeration of databases to retrieve all data of interest. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".

**If it is a computer/service account, the attacker can forge an RC4-encrypted Kerberos silver ticket and impersonate a privileged account to the host or the service.**

ing NTLM responses for cracking. Responder is the most well-known and widely used tool, but Inveigh and Farmer deserve an honorable mention, too. 
 An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2, to recover the password if it is not sufficiently strong . In the case of NTLMv1, the NT hash can always be recovered, and it can be abused in a couple of ways. If it is a computer/service account, the attacker can forge an RC4-encrypted Kerberos silver ticket and impersonate a privileged account to the host or the service. The NT hash can also be used for NTLM authentication, without cracking the cleartext password, through the infamous Pass the Hash attack. 
 Pass the Hash 
 When taking a closer look at the NTLMv1 and NTLMv2 flows, you may notice that, technically, we don’t need the cleartext password to produce a valid NTLM response. If we skip the first step in the flow, the NT hash is all we need. 
 
 
 Who Nee

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it is a computer/service account, the attacker can forge an RC4-encrypted Kerberos silv".

**A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.**

Kerberos preauthentication exists so that a wrong password produces an encrypted timestamp the client cannot produce — the KDC proves the client knows the key. Disable it and the AS-REP comes back regardless of whether the supplied credential is valid, and the reply is encrypted with the account password hash. The attack is: enumerate accounts with preauthentication disabled (an ordinary domain account is enough), send an AS-REQ without the encrypted timestamp to each, collect the AS-REPs, crack them offline. Because the enumeration step is LDAP and the cracking step is local, both halves leave different traces — an LDAP query sweeping the userAccountControl bit, then a burst of offline work on the one host. Check the userAccountControl flag as a baseline control: preauthentication is on by default, so any account with it off is a deliberate exception and worth its own ticket.

*Disproof:* If enumeration returns no accounts with preauthentication disabled, or an AS-REQ without an encrypted timestamp is rejected with KDC_ERR_PREAUTH_REQUIRED for every account tested, then no AS-REP material exists and the attack has no precondition.

**A Kerberos service ticket whose SPN is issued to an account with no interactive login (a service principal) is an offline password-cracking oracle when the KDC still protects it with RC4, because the ticket's encrypted part is keyed on the account password hash.**

Kerberoasting needs no privilege at all: any domain principal can request a TGS ticket for any SPN it names, and the KDC will return one encrypted with that SPN's account key. When that key is RC4 (etype 23), the returned ciphertext is crackable offline with no further interaction with the domain — the whole attack happens locally after a single request. Test procedure: request a service ticket for a target SPN with any low-privilege domain credential, record the etype and cipher, then attempt to crack the ticket offline. A domain that has globally disabled RC4 for service tickets makes this untestable in the classic form, which is exactly the mitigation ATT&CK names. The interesting hunting signal is not the crack but the request pattern: many distinct SPNs requested by one principal in a short window is a request shape that legitimate administration does not produce.

*Disproof:* If the KDC refuses to issue service tickets to requesting users' RC4 (etype 23 is globally disabled), or every crackable ticket offline fails to recover the account password, then this class is not exploitable in this environment and the finding is a false positive.

**Kerberoasting targets service tickets for accounts with a pre-authentication setting that permits it, and the returned ticket is cracked offline for the account password.**

In practice on HTB this shows up as: | `cat .\ilfreight_tgs.csv` | Used to view the contents of the .csv file from a Windows-based host. |
| `.\Rubeus.exe` | Used to view the options and functionality possible with the tool `Rubeus`. Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /stats` | Used to check the kerberoast stats (`/stats`) within the target Windows domain from a Windows-based host. |
| `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap` | Used to request/download TGS tickets for accounts with the `admin` count set to `1` then formats the output in an easy to view & crack manner (`/nowrap`) . Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /user:testspn /nowrap` | Used to request/download a TGS ticket for a specific user (`/user:testspn`) the formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/13. Active Directory Enumeration & Attacks.md (6753 words, classified network).

*Disproof:* Refuted when no account has a non-empty SPN or the accounts that do are configured not to require pre-authentication, in which case no roastable ticket is obtainable.

**Possession of the KRBTGT account password hash is sufficient to forge arbitrary Kerberos ticket-granting tickets for any principal in the forest, because KRBTGT is the key that signs and encrypts every TGT in that domain.**

KRBTGT is a single account whose key is shared by every TGT the KDC issues, so it converts a single-credential compromise into domain-wide ticket forgery: any identity, any ticket lifetime, any group membership, forged at will. This is why rotating KRBTGT twice is the accepted containment step — one rotation does not invalidate tickets already in circulation because the previously active key still validates them. Obtain the hash via credential dumping on a domain controller, then mint a ticket for a target user. The forensic asymmetry worth hunting for: forged tickets can carry lifetimes no KDC would ever issue, because the forger picks the ticket times rather than having them negotiated. Correlating ticket lifetime against issuance time catches tickets that no legitimate AS exchange could have produced.

*Disproof:* If KRBTGT cannot be dumped (credential protection intact, PAW/Protected Users enforced) or a ticket minted from the hash is rejected by a domain controller, then no forged TGT is usable and the class does not apply here.

**An AD account with a service principal name set is requestable by any authenticated domain principal, and the returned ticket is encrypted with the account's own long-term key, so the SPN inventory is the precondition that makes offline key recovery a single request away.**

What the primitive gives you: the SPN list. Tenable states that Kerberoasting is an abuse of the Kerberos protocol to harvest password hashes from Active Directory, and that if a user (service) account has an SPN set, any authenticated user can request service tickets for that account, with the returned ticket encrypted with the NTLM hash of the account's password. The precondition the next link needs is precisely this: a TGT for any domain principal, because the client must present its TGT to request the service ticket for that specific service. Observation that proves the precondition holds: a TGS-REQ for a named SPN returns STATUS_OK and a service ticket whose decryption key is the target account's long-term key. Point-in-time scanning is not enough here, since Tenable notes that point-in-time scans risk missing active threats like Kerberoasting.

*Disproof:* If the domain enforces AES-only service tickets and the SPNs are all AES with long keys, or if no low-privilege principal holds a TGT at all, the request fails or the returned ticket is not crackable with the assumed key material, and the technique has no entry point.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ad_kerberos.auto.01` — ad_kerberos: observe, exercise, confirm (goal: `Establish, exercise and confirm a ad_kerberos condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Counting system SPNs toward a unique-SPN Kerberoasting threshold produces a false positive, because system SPNs exist in nearly every corporate environment and are irrelevant to the attack.**

The lookalike is a domain where the unique-SPN count crosses the alerting threshold even though no roasting occurred. The cause is arithmetic, not adversary behaviour: every domain carries a large fixed set of system SPNs on KRBTGT and the replication pseudo-accounts, and those SPNs are present whether or not anyone attacks. Counting them inflates every client's total and pushes legitimate hosts over the line. Detection logic must exclude system SPNs before applying the threshold, and it must count only unique sname values per client rather than raw response counts, because a raw count cannot distinguish one client fanning out over many services from many clients each asking for one service. Anything built on a raw TGS-REP counter will generate high-volume false positives in a normal estate.

*Disproof:* If a per-client unique-SPN count computed with system SPNs excluded stays below threshold across the estate's normal traffic for a full business cycle, then the threshold was being inflated by system SPNs and the flagged alerts were false positives.

**A single Kerberos 4769 service-ticket event is not evidence of Kerberoasting unless it also shows RC4 request, a user account and a burst pattern.**

Discard the finding when the only observation is one 4769 record, or when the ticket was requested with AES encryption by a machine account, because the source states a service ticket request is legitimate activity and none of its indicators are malicious by itself. It survives when 4769 shows encryption type 0x17 requested by a user account for many different services in a short window.

*Disproof:* Would be wrong if a domain is hardened so that every 4769 originates from machine accounts using AES, since then the account-name signal alone carries no information.

**The number of accounts with an SPN is not itself a Kerberoasting finding; the finding needs a cracked or reusable ticket to survive.**

Discard when the report counts SPNs and requests tickets but shows no recovered secret: a ticket is only encrypted with the account hash, so a 25-character or gMSA-managed password makes the roasting step ineffective and the artefact is configuration, not compromise. It survives when an actual ticket was extracted and either cracked to cleartext or replayed successfully.

*Disproof:* Would be wrong for a domain whose service accounts all carry short dictionary passwords, where ticket extraction alone is already sufficient for compromise.
**Hypothesis:** Host is Kerberoasting: one client requested TGS tickets for many SPNs in a short window
- Invalidated by: the excess was entirely system SPNs, which exist in nearly every corporate environment regardless of adversary activity; the corrected unique non-system SPN count sat below threshold across a full business cycle
- **Rejection rule:** a Kerberoasting threshold that counts system SPNs or raw response packets is invalid; require a per-client count of unique non-system sname values before calling the fan-out an attack

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1558/001/>
  - <https://attack.mitre.org/techniques/T1558/003/>
  - <https://attack.mitre.org/techniques/T1558/004/>
- **capec.mitre.org** (taxonomy)
  - <https://capec.mitre.org/data/definitions/191.html>
  - <https://capec.mitre.org/data/definitions/497.html>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat.md>
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing>
  - <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4120.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/kerberos/kerberoast>
- **zscaler.com** (writeup)
  - <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
