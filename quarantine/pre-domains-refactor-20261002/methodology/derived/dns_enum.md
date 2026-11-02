# Methodology — DNS Enumeration

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class dns_enum --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** DNS names hosts and services, so a zone disclosure enumerates the network without touching it.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the correct behaviour.**

Decide the expectation before reporting. Zone transfer is not an attack primitive in itself: it is the mechanism by which a secondary obtains a copy of the zone, and a secondary will poll the primary to see if the serial number for the zone has increased so it knows to request a new copy of the data for the zone. The precondition for calling an AXFR attempt a finding is therefore an inventory question, not a probe question: does this nameserver have configured secondaries whose legitimate replication traffic you would also see? Enumerate the SOA and NS records for the zone, compare the declared secondaries against the set of hosts you are authorised to test, and only then attempt the transfer. If a transfer succeeds from a nameserver with no declared secondary, or succeeds from a host outside the declared secondary set, that is a genuine disclosure. If it is refused everywhere, that is a closed zone and belongs in validation, not in enumeration. Record which nameservers answered, which refused, and what the SOA serial was before and after, so the report distinguishes a designed configuration from an exposure.

- *Disproof:* The claim is wrong, and a refused or silent AXFR is not a clean configuration, if the transfer succeeds from a nameserver that is not in the zone's declared secondary set, or if a secondaries-permitted ACL is missing so any address can pull the whole zone. Success from a non-secondary address is the disproof for the expectation claim; but note that refusal from a genuinely non-secondary server does prove the zone is closed for that host, so the expectation still holds there.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/catalogue/paths); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1912.html)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.**

DNS is a name-to-address mapping in which the zone is the complete inventory of a namespace, and RFC 1035 defines AXFR as a request for a transfer of an entire zone. That is the whole attack: query the server for a transfer and read the record set. In Windows environments DNS carries additional weight because the DNS Client service uses it to discover domain controllers before authentication even begins — the domain controller location mechanism is a DNS query, so zone contents describe the authentication topology as well as the host list. The control is therefore narrow and checkable: a zone transfer should only be accepted from the secondary servers that need it, and any AXFR answered to an unexpected source is a finding on its own. Note also that SRV records carry service locations, so a zone dump enumerates services, not merely hosts.

- *Disproof:* If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1035.html)

**The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.**

Order the enumeration so the transfer is interpretable. Passive and active DNS enumeration, web crawling, web archive analysis and HTTP header review together build the candidate name list; from that list pull the NS set for the parent and the SOA for the zone, which names the primary and the responsible mailbox and gives the refresh, retry, expire and minimum timers that describe how secondaries are meant to be served. That gives you the expected answer to every AXFR question before you send one. Then run the transfer and diff: names that appear in the transfer but in no NS, SOA, MX, or service record are exactly the internal names the public surface concealed, and those are the entries worth carrying into asset inventory. A transfer that only returns records already derivable from public queries adds no attack surface and should not be scored as a disclosure.

- *Disproof:* The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/catalogue/paths); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1035.html)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A zone-transfer disclosure is validated only by showing a full multi-record answer whose SOA serial is current and whose names exceed the public NS/SOA/MX set, because an empty or serial-stale answer is a replica, not a disclosure.**

Three checks separate a real disclosure from a noisy probe. First, serial: the returned SOA serial must equal or be newer than the serial a plain SOA query returns; if it is older, you are reading a stale replica and your record set is not authoritative. Second, completeness: a genuine transfer returns the SOA plus the full RRset for every zone owner, not a truncated subset; the transfer is of an entire zone by definition, so a partial answer is either a transfer in progress or a deliberately limited reply and neither is a clean copy. Third, delta: subtract every record derivable from NS, SOA, MX, TXT and service-record queries, then count the remainder. Only the remainder is new attack surface. Record the count of names recovered and the sources they came from, because a transfer that returns nothing beyond the public set is a closed zone, and one that returns a current serial plus internal names is a finding that justifies the follow-on takeover and virtual-host work.

- *Disproof:* The validation fails, and the transfer is not a disclosure, if the returned SOA serial is older than the publicly queryable serial (stale replica); the answer contains the SOA but no additional owner names; every returned record was already obtainable through normal public queries; or the transfer succeeded only from an address inside the declared secondary set, which is the designed replication path rather than an exposure. A current serial plus at least one name absent from the public set is what the finding requires.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/catalogue/paths); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1035.html)

**A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.**

Validation: enumeration tools list an attempt to transfer a DNS zone as a module, and separately list subdomain enumeration by NSEC-walking, TXT record inspection, and reference hunting in page content. These produce very different evidence, and a failed transfer is routinely reported as a successful enumeration because the module simply ran. The validation rule is that a record set must exist before the observation counts. Compare against what a real anonymous retrieval looks like on a device that has one: a single crafted TFTP get request causes a file download, resulting in disclosure of sensitive information, and the attacker can send unauthenticated commands to trigger it. That is the shape of positive evidence: content actually came back, unauthenticated. For DNS the equivalent is a SOA plus NS record set plus the additional records returned, or a proven NSEC chain walked to NXDOMAIN. What a refusal proves is a control: the zone is not AXFR-open, which is a hardening fact worth recording, not an exposure. Two further corrections belong with the finding. A zone transfer that returns only SOA and NS is a misconfigured delegation, not a full enumeration. And subdomain names recovered from certificate transparency, search engines, or other external means are not DNS enumeration against the target at all; label them as passive so the active-path claim stays honest.

- *Disproof:* The transfer or an equivalent anonymous read returns an actual record set beyond SOA and NS, or an NSEC chain yields NXDOMAIN proofs for names that resolve elsewhere, showing records were retrieved without authentication.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.**

The transfer request is a transfer of an entire zone, and a properly configured primary answers it only for hosts it is configured to serve secondaries. A zone transfer is UDP-unacceptable by design, and the SOA reply that accompanies a refusal is the normal authoritative signal, not a partial leak. So the discriminator is not whether the probe returned records; it is whether any authoritative server served the zone to an address outside its declared secondary set. Reject when: every authoritative NS returns REFUSED, NOTAUTH, or an empty answer with SOA present; the refusal is consistent from two or more source addresses and over both TCP and the fallback path; and the SOA serial returned matches the serial obtainable by a plain SOA query, which proves the transfer revealed nothing the public surface did not already publish. Report as a validated negative, and do not carry it into the enumeration hit list.

- *Disproof:* The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/catalogue/paths); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1035.html)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those names are the ones still pointing at de-provisioned third-party services.**

Two published facts compose. First, the enumeration delta: a transfer is of an entire zone, and a secondary polls the primary when the serial increases, so a successful transfer returns every owner name in the zone rather than the subset that NS, SOA, MX and service records expose. Second, the takeover precondition: attackers abuse the trust of a still-registered owner name rather than of the expired domain, because the DNS record outlives the third-party service it pointed at, which is what makes the dangling name claimable. Composed: the internal names recovered only by transfer are fed into a dangling-record check, each candidate is resolved and probed for an unclaimed service fingerprint, and any candidate that answers with a vendor no-longer-provisioned page becomes an attacker-controlled host inside the target's own domain. The chain matters because the transfer is the only cheap source of names that were never in public CT logs, so it widens the takeover search from what a certificate crawl would have found to the whole zone.

- *Disproof:* The chain is refuted if the zone transfer is refused or returns nothing beyond the public NS and SOA set, leaving no name the certificate sources missed; or if every transferred name resolves to an active, correctly provisioned service, so nothing is claimable; or if the recovered internal names sit outside the registrable domain and therefore outside any session cookie's Domain scope, making a takeover phishing-only rather than session-affecting. The transfer must produce at least one live dangling record for the chain to end anywhere.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/catalogue/paths); [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1035.html)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
