# Methodology — Kerberos Authentication Weaknesses

> Derived from 11 verified items. Regenerate with `python -m wks.methodgen --class ad_kerberos --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.

**References.** CWE-287

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A single host receiving TGS-REP responses for numerous unique SPNs inside a short window is an early observable for Kerberoasting but is identical to legitimate service-ticket traffic.**

The fan-out shape to alert on is one client name, many unique service names, one time window, all non-system service accounts. Kerberoasting produces exactly this because a single TGT holder requests TGS tickets for many SPNs in sequence. What makes it only a signal: the TGS ticket requests an attacker makes are byte-for-byte the same as ordinary legitimate requests, and every domain generates a high volume of Kerberos traffic, so there is no signature to match on. A management server, a monitoring agent, or an SAP/mail client that legitimately services many SPNs produces the same fan-out. Treat the shape as the hypothesis generator and go looking for which service accounts were in the fan-out and whether they are non-system accounts whose password age makes offline cracking plausible.

- *Disproof:* If the unique SPNs in the window resolve to a single known management or monitoring principal that is documented to service that SPN set on a schedule, then the fan-out is the agent's normal behaviour and the Kerberoasting hypothesis for that host is invalidated.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A Kerberos service ticket whose SPN is issued to an account with no interactive login (a service principal) is an offline password-cracking oracle when the KDC still protects it with RC4, because the ticket's encrypted part is keyed on the account password hash.**

Kerberoasting needs no privilege at all: any domain principal can request a TGS ticket for any SPN it names, and the KDC will return one encrypted with that SPN's account key. When that key is RC4 (etype 23), the returned ciphertext is crackable offline with no further interaction with the domain — the whole attack happens locally after a single request. Test procedure: request a service ticket for a target SPN with any low-privilege domain credential, record the etype and cipher, then attempt to crack the ticket offline. A domain that has globally disabled RC4 for service tickets makes this untestable in the classic form, which is exactly the mitigation ATT&CK names. The interesting hunting signal is not the crack but the request pattern: many distinct SPNs requested by one principal in a short window is a request shape that legitimate administration does not produce.

- *Disproof:* If the KDC refuses to issue service tickets to requesting users' RC4 (etype 23 is globally disabled), or every crackable ticket offline fails to recover the account password, then this class is not exploitable in this environment and the finding is a false positive.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1558/003/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/294.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

**An AD account with a service principal name set is requestable by any authenticated domain principal, and the returned ticket is encrypted with the account's own long-term key, so the SPN inventory is the precondition that makes offline key recovery a single request away.**

What the primitive gives you: the SPN list. Tenable states that Kerberoasting is an abuse of the Kerberos protocol to harvest password hashes from Active Directory, and that if a user (service) account has an SPN set, any authenticated user can request service tickets for that account, with the returned ticket encrypted with the NTLM hash of the account's password. The precondition the next link needs is precisely this: a TGT for any domain principal, because the client must present its TGT to request the service ticket for that specific service. Observation that proves the precondition holds: a TGS-REQ for a named SPN returns STATUS_OK and a service ticket whose decryption key is the target account's long-term key. Point-in-time scanning is not enough here, since Tenable notes that point-in-time scans risk missing active threats like Kerberoasting.

- *Disproof:* If the domain enforces AES-only service tickets and the SPNs are all AES with long keys, or if no low-privilege principal holds a TGT at all, the request fails or the returned ticket is not crackable with the assumed key material, and the technique has no entry point.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview); [tenable.com](https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link)

**A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.**

Kerberos preauthentication exists so that a wrong password produces an encrypted timestamp the client cannot produce — the KDC proves the client knows the key. Disable it and the AS-REP comes back regardless of whether the supplied credential is valid, and the reply is encrypted with the account password hash. The attack is: enumerate accounts with preauthentication disabled (an ordinary domain account is enough), send an AS-REQ without the encrypted timestamp to each, collect the AS-REPs, crack them offline. Because the enumeration step is LDAP and the cracking step is local, both halves leave different traces — an LDAP query sweeping the userAccountControl bit, then a burst of offline work on the one host. Check the userAccountControl flag as a baseline control: preauthentication is on by default, so any account with it off is a deliberate exception and worth its own ticket.

- *Disproof:* If enumeration returns no accounts with preauthentication disabled, or an AS-REQ without an encrypted timestamp is rejected with KDC_ERR_PREAUTH_REQUIRED for every account tested, then no AS-REP material exists and the attack has no precondition.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1558/004/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4120.html)

**Possession of the KRBTGT account password hash is sufficient to forge arbitrary Kerberos ticket-granting tickets for any principal in the forest, because KRBTGT is the key that signs and encrypts every TGT in that domain.**

KRBTGT is a single account whose key is shared by every TGT the KDC issues, so it converts a single-credential compromise into domain-wide ticket forgery: any identity, any ticket lifetime, any group membership, forged at will. This is why rotating KRBTGT twice is the accepted containment step — one rotation does not invalidate tickets already in circulation because the previously active key still validates them. Obtain the hash via credential dumping on a domain controller, then mint a ticket for a target user. The forensic asymmetry worth hunting for: forged tickets can carry lifetimes no KDC would ever issue, because the forger picks the ticket times rather than having them negotiated. Correlating ticket lifetime against issuance time catches tickets that no legitimate AS exchange could have produced.

- *Disproof:* If KRBTGT cannot be dumped (credential protection intact, PAW/Protected Users enforced) or a ticket minted from the hash is rejected by a domain controller, then no forged TGT is usable and the class does not apply here.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1558/001/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4120.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**The number of accounts with an SPN is not itself a Kerberoasting finding; the finding needs a cracked or reusable ticket to survive.**

Discard when the report counts SPNs and requests tickets but shows no recovered secret: a ticket is only encrypted with the account hash, so a 25-character or gMSA-managed password makes the roasting step ineffective and the artefact is configuration, not compromise. It survives when an actual ticket was extracted and either cracked to cleartext or replayed successfully.

- *Disproof:* Would be wrong for a domain whose service accounts all carry short dictionary passwords, where ticket extraction alone is already sufficient for compromise.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)

**Counting system SPNs toward a unique-SPN Kerberoasting threshold produces a false positive, because system SPNs exist in nearly every corporate environment and are irrelevant to the attack.**

The lookalike is a domain where the unique-SPN count crosses the alerting threshold even though no roasting occurred. The cause is arithmetic, not adversary behaviour: every domain carries a large fixed set of system SPNs on KRBTGT and the replication pseudo-accounts, and those SPNs are present whether or not anyone attacks. Counting them inflates every client's total and pushes legitimate hosts over the line. Detection logic must exclude system SPNs before applying the threshold, and it must count only unique sname values per client rather than raw response counts, because a raw count cannot distinguish one client fanning out over many services from many clients each asking for one service. Anything built on a raw TGS-REP counter will generate high-volume false positives in a normal estate.

- *Disproof:* If a per-client unique-SPN count computed with system SPNs excluded stays below threshold across the estate's normal traffic for a full business cycle, then the threshold was being inflated by system SPNs and the flagged alerts were false positives.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

**A single Kerberos 4769 service-ticket event is not evidence of Kerberoasting unless it also shows RC4 request, a user account and a burst pattern.**

Discard the finding when the only observation is one 4769 record, or when the ticket was requested with AES encryption by a machine account, because the source states a service ticket request is legitimate activity and none of its indicators are malicious by itself. It survives when 4769 shows encryption type 0x17 requested by a user account for many different services in a short window.

- *Disproof:* Would be wrong if a domain is hardened so that every 4769 originates from machine accounts using AES, since then the account-name signal alone carries no information.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack them offline without triggering account lockout.**

The two halves are each documented and the join is direct. The kerberoasting lab states that it allows any domain user to request kerberos tickets from TGS that are encrypted with the NTLM hash of the plaintext password of a domain user account used as a service account, and to crack them offline avoiding AD account lockouts. The lab marks the vulnerable domain member as a user account with the servicePrincipalName attribute set, which is very important piece for kerberoasting, and gives the enumeration command that produces the input: Get-NetUser filtered on servicePrincipalName. That filter is the chain link. Directory enumeration returns the account names; the filter selects the subset with an SPN; the ticket request converts each name into a crackable hash. CAPEC's file-discovery entry supplies the general framing for the enumeration half, noting that such files often contain configuration and security parameters of the targeted application, system or network. For a hunter the operational consequence is that an enumeration finding should be escalated on the strength of what it enables, not on the enumeration itself: a readable SPN list with RC4 still permitted is a credential compromise in progress, and the absence of lockout events means nothing has failed visibly.

- *Disproof:* If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/497.html); [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md)

**An account flagged Do not require Kerberos preauthentication can be turned into a password hash by any domain user, because the AS-REP returned in place of a pre-authentication exchange is encrypted with that user's NTLM hash.**

AS-REP roasting is the passive sibling of kerberoasting and is a cleaner finding because it needs no SPN at all. The lab defines it as a technique that allows retrieving password hashes for users that have the Do not require Kerberos preauthentication property selected, and notes the hashes can then be cracked offline exactly as in kerberoasting. The detection view states the same asymmetry from the attacker side: an attacker can request TGTs for these users without knowing their password, the TGTs are encrypted with the user's NTLM hash, and a successful offline crack yields the plaintext password. Because the condition is a single boolean on the user object, a single non-compliant account is sufficient to make the whole roast productive, and the attacker learns which accounts qualify from directory enumeration rather than from any failure signal.

- *Disproof:* Refuted if preauthentication is enforced for every user in the domain, or if all qualifying accounts hold passwords of high enough entropy that offline cracking fails; the roast still succeeds but yields nothing.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat.md); [zscaler.com](https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection)

**Kerberoasting is available to any domain user because the service ticket returned for a service principal name carries a portion encrypted with the service account's NTLM hash, which the attacker cracks offline without ever touching that account's password.**

Two independent vendors describe the same mechanism. The lab framing is that it allows any domain user to request Kerberos tickets from the TGS that are encrypted with the NTLM hash of the plaintext password of a domain user account used as a service account, and those tickets can be cracked offline, avoiding AD account lockouts. The detection-engineering framing adds the operational detail: attackers request Kerberos service tickets for the SPNs, the issued ticket contains a portion encrypted with the service account's NTLM hash, and that portion is extracted and cracked with brute force or dictionary attacks. Crucially, legacy RC4 keying makes the crack far faster, so a domain that still supports RC4 for backward compatibility converts a low-privilege foothold into a password-hash corpus with no failed logins generated anywhere.

- *Disproof:* Refuted if every service principal name is mapped to an account whose password is a random value of high entropy, or if the domain has disabled RC4 so tickets are AES-encrypted and offline cracking is impractical.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md); [zscaler.com](https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
