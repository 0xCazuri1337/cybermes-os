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
