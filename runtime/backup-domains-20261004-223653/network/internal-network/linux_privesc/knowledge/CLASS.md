# Linux Privilege Escalation

## Definition

A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.

- **CWE:** CWE-269
- **OWASP:** A01:2021
- **Surface:** net
- **Aliases:** []

Canonical home for `linux_privesc`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.**

The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

*Disproof:* The running sudo version is outside the vulnerable range or has chroot support compiled out.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.**

A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.

HackTricks reference: euid ruid suid (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md)

*Disproof:* Every process shows euid equal to ruid, meaning no set-user-ID transition occurred.

## Exploitation

**Academy documents CVE-2018-15133 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Academy (official write-up, doc 297, 14484 chars, sha1 14299dce829c) describes CVE-2018-15133. Mechanism as documented on the machine: $payload = $this->getJsonPayload($payload); $iv = base64_decode($payload['iv']); $decrypted = \openssl_decrypt(

Authoritative record: In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur,

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-15133) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Compromised documents CVE-2018-12256 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Compromised (official write-up, doc 276, 33064 chars, sha1 bde6aef3ebdd) describes CVE-2018-12256. Mechanism as documented on the machine: A Google search for this specific version reveals that it is vulnerable to an Authenticated Arbitrary File Upload exploit, which is assigned CVE-2018-12256. The vulnerability can be exploited through the usage of the LiteCart admin panel that was identified in the downloaded backup. We do not currently possess valid credentials for the panel.

Authoritative record: admin/vqmods.app/vqmods.inc.php in LiteCart before 2.1.3 allows remote authenticated attackers to upload a malicious file (resulting in remote code execution) by using the text/xml or application/xml Content-Type in a public_html/admin/?app=vqmods&doc=vqmods request.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-12256) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Paper documents CVE-2019-17671 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Paper (official write-up, doc 432, 9468 chars, sha1 ef3dcbe676b7) describes CVE-2019-17671. Mechanism as documented on the machine: Upon running a quick Google search along with the keywords "wordpress 5.2.3 exploits", we can identify CVE-2019-17671 which allows a user to view private/draft posts without authentication. This vulnerability aligns perfectly with the suspicious comment that we found earlier. Let us exploit this vulnerability to view the secret content present in the draft posts. To do so, we can add ?static=1 to the WordPress URL as mentioned in the PoC.

Authoritative record: In WordPress before 5.2.4, unauthenticated viewing of certain content is possible because the static query property is mishandled.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-17671) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Paper documents CVE-2021-3560 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Paper (official write-up, doc 432, 9468 chars, sha1 ef3dcbe676b7) describes CVE-2021-3560. Mechanism as documented on the machine: The exploit was successfully able to create a new user with sudo privileges. The root flag can be found at /root/root.txt .

Authoritative record: It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3560) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.**

Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

*Disproof:* The sudo version is unaffected, or no sudoers rule is qualified by a specific host.

**If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.**

If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

*Disproof:* The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.linux_privesc.auto.01` — linux_privesc: observe, exercise, confirm (goal: `Establish, exercise and confirm a linux_privesc condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.

Adjacent behaviour that produces the same observable result: If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

Adjacent behaviour that produces the same observable result: A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

**Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.**

Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.

HackTricks reference: ld.so.conf example (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md)

*Disproof:* The resolved object list is identical with and without the cache, so no cache-based selection occurred.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/200.html>
  - <https://cwe.mitre.org/data/definitions/269.html>
  - <https://cwe.mitre.org/data/definitions/434.html>
  - <https://cwe.mitre.org/data/definitions/502.html>
  - <https://cwe.mitre.org/data/definitions/863.html>
- **man7.org** (research)
  - <https://man7.org/linux/man-pages/man2/execve.2.html>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md>
- **services.nvd.nist.gov** (research)
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-12256>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-15133>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-17671>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
