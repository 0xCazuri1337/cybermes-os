# Methodology — DNS Enumeration

> Derived from 8 verified items. Regenerate with `python -m wks.methodgen --class dns_enum --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**A negative answer from a DNSSEC-signed zone that uses NSEC rather than NSEC3 carries the next existing owner name in its authority section, so an anonymous client can follow that chain and walk the whole zone without an AXFR.**

A DNSSEC-signed zone has to prove that a name which does not exist really does not exist, and it does that with an NSEC record in the authority section of the NXDOMAIN response: the record names its own owner, a type bitmap, and the next owner name in the zone's canonical (lexicographic) ordering. Because that next name is the successor of the name you asked for, an anonymous queryer recovers the zone one successor at a time -- request a random label, read the next-domain field out of the response, then request that name and repeat until the chain wraps back to the apex. No AXFR, no authenticated session and no wordlist are needed: this is the same disclosure a refused zone transfer denies, so a refused AXFR is not evidence that the zone is closed. Two states remove the walk and must be established before it is claimed -- NSEC3 hashes the owner and next-owner names, and minimally covering NSEC records bracket only the queried label. Probe the authoritative nameserver directly rather than a recursive resolver, verify that each recovered name resolves on its own, and compare the recovered set against the public NS/SOA/MX set so only names the public surface concealed are scored.

- *Disproof:* Wrong if the zone publishes NSEC3 rather than NSEC, because the owner and next-owner names are salted hashes and no plaintext successor is returned to follow; equally wrong if minimally covering NSEC records are served, since the span then brackets only the queried label and nothing else is disclosed. Also wrong if the authority section of the negative response is empty, which is the unsigned or opt-out case where one name is never linked to the next. A walk that terminates after a single query, or that returns only names already obtainable from NS, SOA, MX and service-record queries, reveals nothing the public surface did not already publish.
- *Evidence:* high_confidence — [blog.apnic.net](https://blog.apnic.net/2023/01/17/subdomain-enumeration-with-dnssec/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4034.html); [svn.nmap.org](https://svn.nmap.org/nmap/scripts/dns-nsec-enum.nse)

**Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.**

In practice on HTB this shows up as: -   `IXFR` - Incremental Zone Transfer
An `AXFR` is a complete transfer of all entries of the zone file. In contrast to full asynchronous transfer, only the changed and new DNS records of the zone file are transferred for an `IXFR` to the secondary DNS servers.
The problem with DNS servers and zone transfers is that it does not require authentication and can be requested by any client. If the administrator has not set "Trusted Hosts/IP addresses" for the DNS servers, which have permission to receive these zones, we can also query the entire zone file with its contents. This will give us all IP addresses with the respective hosts and significantly increase our attack vector if the agreement does not limit our scope. Even today, it is quite common that the DNS servers are misconfigured and allow this.

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/02. Information Gathering/10b. DNS Enumeration Python/DNS Enumeration Using Python.md (8215 words, classified network).

- *Disproof:* Refuted when the authoritative server refuses AXFR and out-of-zone queries, so the internal inventory is never returned.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1016/001/); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10b.%20DNS%20Enumeration%20Python/DNS%20Enumeration%20Using%20Python.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1035.html)

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
