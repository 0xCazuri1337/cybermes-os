# Methodology — Internal Network Reconnaissance

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class internal_recon --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**References.** CWE-200

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**

RFC 1918 states the consequence directly: addresses in private space are unique only within the enterprise, or among cooperating enterprises, so a private address identifies a host only relative to a vantage point inside the same space. That is the reason internal recon is inference: a DHCP-assigned address in a segment that conventionally serves a particular role is evidence about what runs there, and the reverse mapping — the address you can reach, the name you can resolve — is what turns reachability into a map. Two operational rules follow. First, private addresses must not be propagated across inter-enterprise links, so a private address appearing in external DNS records or leaked logs is itself an information disclosure. Second, because renumbering is costly, address-to-role mappings are stable, which is exactly what makes them predictive and worth enumerating deliberately rather than by opportunistic scanning.

- *Disproof:* If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
- *Evidence:* high_confidence — [iana.org](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1918.html)

**If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**

h no edits. ","attrs":{"style":{"font-size":"11pt"}}}]},{"uid":"926c1ce8624240f59b682fbc73990e0a","type":"esqlSnippet","attrs":{"code":"/*\n Broad sweep: hunt one user's activity across every linked project.\n*/\nFROM logs-* METADATA _index\n /* METADATA _index is your project attribution. Linked-project rows arrive\n with the project alias as an index prefix; there is no ECS \"project\"\n field. If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. Dragging full _source at depth was many times\n slower than projecting columns in our testing. If a cross-project query\n feels slow, check this before you blame the fan-out. */\n| SORT @timestamp DESC\n| LIMIT 500"},"children":[{"text":""}]},{"uid":"acbee15c9fcd40d29fc72518a4df15d2","type":"p","children":[{"text":""}],"attrs":{}},{"uid":"36f15cd16e8c4b6b9a44352c47a0c767","type":"image","attrs":{

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If you need to know which tenant an event came from, this is how. */\n| WHERE us”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [elastic.co](https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language)

**Service enumeration with nmap -sV and -sC identifies running services and their versions on discovered internal hosts.**

Run nmap -sV -sC -p- against live hosts to detect services and versions. Focus on domain controllers (88, 389, 445), databases (1433, 3306, 5432), and internal web apps. Version detection reveals patch levels and known vulnerabilities; NSE scripts extract additional metadata like SMB shares and LDAP naming contexts.

- *Disproof:* All ports are filtered or closed, or service detection returns no version information.
- *Evidence:* high_confidence — [charlesreid1.com](https://charlesreid1.com/wiki/Nmap/Short_Course/Lecture_8); [nmap.org](https://nmap.org/book/man-briefoptions.html)

**Internal host discovery begins with a ping sweep or ARP scan to enumerate live hosts on adjacent subnets before port scanning.**

From a compromised foothold, run nmap -sn or an ARP sweep (arp-scan, netdiscover) against the local /24 and adjacent subnets. ARP-based discovery is stealthier and more reliable on the local segment than ICMP. Live hosts become the target list for subsequent port and service enumeration.

- *Disproof:* No live hosts respond to ARP/ICMP, or host discovery is blocked by network segmentation and VLAN ACLs.
- *Evidence:* supported — [charlesreid1.com](https://charlesreid1.com/wiki/Nmap/Short_Course/Lecture_8); [nmap.org](https://nmap.org/book/man-briefoptions.html)

**When direct access is unavailable, a compromised host acts as a pivot point via SOCKS proxy or SSH tunnel to reach internal networks.**

Establish a SOCKS proxy with ssh -D or a tunnel through the compromised host, then route scanning tools via proxychains. This relays reconnaissance traffic into subnets not directly reachable from the attacker, enabling internal host and service discovery without deploying tools on the target.

- *Disproof:* No egress path exists from the compromised host, or proxying is blocked by egress filtering.
- *Evidence:* supported — [charlesreid1.com](https://charlesreid1.com/wiki/Nmap/Short_Course/Lecture_8); [hackersmanifest.com](https://hackersmanifest.com/internal-pentest/02-reconnaissance)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.**

A clean process-creation log is therefore not exculpatory, and a hunter who greps command-line telemetry for enumeration arguments will find nothing. Detection has to move to network-side RPC traffic and to the proxy process itself rather than to the command line the operator never typed. The claim is falsified if Sysmon or EDR process telemetry still captures the full argument string for the proxied invocation, which would mean the proxy does not actually strip it from process creation events.

- *Disproof:* If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language); [ired.team](https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md)

## 3. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never touched.**

The chain is three published mechanisms composed, and each handoff is observable. Link one: enumeration returns the account list, and the filter for servicePrincipalName selects the subset that matters - the PowerView course material names exactly this join, describing the tools as useful for finding quick wins such as users that can be attacked via Kerberoasting or ASREPRoasting. Link two: with a low-privileged account and a valid TGT, the adversary requests TGS tickets with weakened encryption for the service accounts carrying SPNs, which does not require any access permission on those services, and cracks the tickets offline with no network activity - the credential that emerges is the service account's plaintext password. Link three: that password is an ordinary credential for every service that authenticates it, so SMB, WinRM, or RDP become authenticated remote-execution channels on hosts the enumeration never listed. This is why directory read access is graded above information disclosure: the enumeration output is not the finding, it is the ammunition. The ceiling on the chain is password policy - accounts generated automatically with complex passwords are not the target, accounts created manually by infrastructure administrators are.

- *Disproof:* Refuted if the directory does not expose servicePrincipalName values to the enumerating principal, or if every SPN-bearing account has a password that offline cracking did not recover within the assessment window; without a recovered service-account secret the chain stops at enumeration.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, False-positive rejection, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
