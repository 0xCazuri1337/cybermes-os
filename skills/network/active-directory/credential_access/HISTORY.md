# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -70,4 +70,4 @@
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/> · <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>
 
 ---
-Full class document: `domains/network/active-directory/credential_access/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
+Full class document: `domains/network/active-directory/credential_access/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
```

## 2026-10-02 19:37 — 48 diff lines
- items: 13 (supported 5), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-522 · OWASP —
-> evidence: 13 items, 13 supported, 2 FP rules, 1 chains
+> evidence: 13 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
@@ -26,28 +26,28 @@
 
 ## Techniques (what to change)
 
-- In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements.
+- In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.
+- The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The current version (v5) was described in RFC1510 back in 1993, although it was updated in".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.
+- This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This prevents an attacker using Kerberos as an encryption oracle and reusing existing encr".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password.
+- If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- This technique does require the attacker to have an account on the KDC to make the service ticket request.
+- This technique does require the attacker to have an account on the KDC to make the service ticket request. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.
+- Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data.
+- Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC.
+- At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
 - The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.
```

## 2026-10-03 01:46 — 42 diff lines
- items: 13 (supported 5), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -28,31 +28,31 @@
 
 - In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
 - The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The current version (v5) was described in RFC1510 back in 1993, although it was updated in".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
 - This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This prevents an attacker using Kerberos as an encryption oracle and reusing existing encr".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
 - If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
 - This technique does require the attacker to have an account on the KDC to make the service ticket request. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
 - Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 - Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
 - At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
 - The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.
   - **Disproof:** If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
-  - Sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
+  - Sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-04 00:43 — 97 diff lines
- items: 13 (supported 5), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -20,54 +20,69 @@
 
 ## Recon signals (where to look)
 
-- An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.
+- An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no authentication event follows the capture that uses the captured hash as NTLM credentials against any target service, and the captured user is shown browsing the share normally, then no credential access occurred and the capture remains an unenacted collection artefact.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
-- In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements. _(unverified)_
+- Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+- At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
+- If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
+- In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption ".
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
-- The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use. _(unverified)_
+- Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
+- The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The current version (v5) was described in RFC1510 back in 1993, although it was updated in".
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
-- This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol. _(unverified)_
+- The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
+  - Sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+- This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This prevents an attacker using Kerberos as an encryption oracle and reusing existing encr".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
-- This technique does require the attacker to have an account on the KDC to make the service ticket request. _(unverified)_
+- This technique does require the attacker to have an account on the KDC to make the service ticket request.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
-- Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
-- At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
-- The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.
-  - **Disproof:** If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
-  - Sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 
 ## False-positive rules (when to reject it)
 
-- Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.
+- A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>
+- Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.  _(merged 1 duplicate row(s))_
   - **Disproof:** Would be wrong in a domain where the Protected Users group has been emptied, since the group membership check would then pass for everyone.
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
-- A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.
-  - **Disproof:** Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>
 
 ## Impact framing
 
-- Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.
+- Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/> · <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/credential_access/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
```

## 2026-10-04 19:46 — 9 diff lines
- items: 13 (supported 5), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -86,6 +86,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/credential_access/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 41 diff lines
- items: 13 (supported 8), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-522 · OWASP —
-> evidence: 13 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 13 items, 8 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
@@ -26,8 +26,8 @@
 
 ## Techniques (what to change)
 
-- Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".
+- Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Also modern versions of Windows Server will try to block this attack by forcing ”) does not occur under a test that isolates that control.
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 - At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
@@ -41,14 +41,14 @@
 - Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
-- The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The current version (v5) was described in RFC1510 back in 1993, although it was updated in".
+- The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The current version (v5) was described in RFC1510 back in 1993, although it was ”) does not occur under a test that isolates that control.
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
 - The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
   - Sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This prevents an attacker using Kerberos as an encryption oracle and reusing existing encr".
+- This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This prevents an attacker using Kerberos as an encryption oracle and reusing exi”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
 - This technique does require the attacker to have an account on the KDC to make the service ticket request.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".
```

## 2026-10-28 15:58 — 52 diff lines
- items: 12 (supported 11), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-522 · OWASP —
-> evidence: 13 items, 8 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
@@ -29,18 +29,9 @@
 - Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Also modern versions of Windows Server will try to block this attack by forcing ”) does not occur under a test that isolates that control.
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
-- If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
 - In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption ".
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
-- Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
 - The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The current version (v5) was described in RFC1510 back in 1993, although it was ”) does not occur under a test that isolates that control.
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
@@ -50,9 +41,18 @@
 - This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This prevents an attacker using Kerberos as an encryption oracle and reusing exi”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
-- This technique does require the attacker to have an account on the KDC to make the service ticket request.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".
-  - Sources: <https://googleprojectzero.blogspot.com/2022/10/>
+
+## Tests
+
+- LSASS memory contains credential material generated by interactive, batch, and service logons; a dump is evidence only when the process memory was read and a credential artifact was recovered, not when a dump file is merely created.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A dump file that yields no credential, or a dump attempt blocked by LSA protection, is not a credential-access finding. LSA protection exists specifically to stop nonprotected processes from reading LSASS memory, so a blocked read is the control working.
+  - Sources: <https://attack.mitre.org/techniques/T1003/001/> · <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>
+- NTDS.dit contains the domain's directory credential material and is located on domain controllers; extracting it requires domain controller access or a directory replication right, and the finding is proven by recovered domain hashes rather than by a copy of the file alone.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A copied NTDS.dit file that yields no domain hashes is not a credential-access finding. The database is present on every domain controller; the finding requires a recovered credential or a demonstrated replication response.
+  - Sources: <https://attack.mitre.org/techniques/T1003/003/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview>
+- The SAM database stores local account credential material, and extracting it requires reading the SAM and SYSTEM registry hives or equivalent in-memory access on the host; a successful extraction is proven by recovered hashes, not by the presence of the files.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A SAM or SYSTEM file that yields no usable hash is not a credential-access finding. The files can be present on every host; the finding requires successful decryption and a recovered credential.
+  - Sources: <https://attack.mitre.org/techniques/T1003/002/> · <https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-28 18:01 — 24 diff lines
- items: 14 (supported 11), FP rules 2, chains 1, state mature

```diff
--- credential_access@current
+++ credential_access@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-522 · OWASP —
-> evidence: 12 items, 11 supported, 2 FP rules, 1 chains
+> evidence: 14 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
@@ -44,6 +44,12 @@
 
 ## Tests
 
+- AS-REP roasting requires a target account that does not require Kerberos preauthentication; the KDC returns data encrypted with the user's key before verifying the client knows that key, allowing offline cracking without an account on the KDC.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If the account requires preauthentication, the KDC does not return a crackable AS-REP blob, so a failed AS-REQ is not evidence. An AS-REP is not a cracked password until the key is recovered.
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat>
+- Kerberoasting requires an authenticated domain account to request a service ticket and a target service account with a registered SPN; the returned ticket is encrypted with the service account's key and can be cracked offline.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If the target account has no SPN, or the ticket uses an encryption type that is not crackable within the engagement's budget, the request is not evidence of a recoverable credential. A service ticket is not a cracked password until the key is recovered.
+  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names>
 - LSASS memory contains credential material generated by interactive, batch, and service logons; a dump is evidence only when the process memory was read and a credential artifact was recovered, not when a dump file is merely created.  _(merged 1 duplicate row(s))_
   - **Disproof:** A dump file that yields no credential, or a dump attempt blocked by LSA protection, is not a credential-access finding. LSA protection exists specifically to stop nonprotected processes from reading LSASS memory, so a blocked read is the control working.
   - Sources: <https://attack.mitre.org/techniques/T1003/001/> · <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>
```

## 2026-10-31 06:41 — 26 diff lines
- items: 14 (supported 9), FP rules 0, chains 1, state researching
- still missing: fp_rules

```diff
--- credential_access@current
+++ credential_access@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-522 · OWASP —
-> evidence: 14 items, 11 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 14 items, 9 supported, 0 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
 
@@ -62,10 +62,10 @@
 
 ## False-positive rules (when to reject it)
 
-- A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.  _(merged 1 duplicate row(s))_
+- A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>
-- Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.  _(merged 1 duplicate row(s))_
+- Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Would be wrong in a domain where the Protected Users group has been emptied, since the group membership check would then pass for everyone.
   - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 14 (supported 9), FP rules 0, chains 1, state researching
- still missing: fp_rules

```diff
--- credential_access@current
+++ credential_access@new
@@ -91,7 +91,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/active-directory/credential_access/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
+Full class document: `skills/network/active-directory/credential_access/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 14 (supported 9), FP rules 0, chains 1, state researching
- still missing: fp_rules

```diff
--- credential_access@current
+++ credential_access@new
@@ -5,7 +5,8 @@
 
 # Windows Credential Access — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
