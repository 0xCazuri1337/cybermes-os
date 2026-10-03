# Methodology — Information Disclosure

> Derived from 14 verified items. Regenerate with `python -m wks.methodgen --class info_disclosure --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Error output, directory listings or metadata reveal more about the system than the caller should learn.

**References.** CWE-200 · A01:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**An internet-exposed SSH, SMB, RDP or Postgres service is discovered and compromised within minutes of exposure, so the exposure-to-compromise window is bounded by minutes rather than by the patch cycle.**

Unit 42 deployed 320 honeypots across North America, APAC and Europe running SSH, Samba, Postgres and RDP and measured the gap between exposure and first successful authentication. 80 percent of the honeypots were compromised within 24 hours and every honeypot within a week; the most attacked SSH honeypot was compromised 169 times in a single day and the average SSH honeypot 26 times daily. One actor compromised 96 percent of the Postgres honeypots globally within 30 seconds. Two results matter for hunting. The exposure-to-compromise interval is minutes, so a remediation SLA expressed in days describes a different world than the one the attacker acts in. And 85 percent of attacker IPs were seen on only a single day, meaning a blocklist generated from yesterday protects nothing today; the study notes layer-3 IP-based firewalls are ineffective for exactly this reason. Detection must move to the authentication layer where the repeated weak-credential pattern is visible even though the source address is new each time.

- *Disproof:* If the exposed service is reachable only from inside a segmented trust boundary, or sits behind an authenticated gateway that rejects anonymous and weak-credential connections, then the minutes-scale compromise window does not apply.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/exposed-services-public-clouds/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A response header naming a specific framework version such as X-AspNet-Version is a passive-signal information disclosure because it lets an attacker select a matching public exploit without further probing.**

ZAP ships a passive scan rule dedicated to this header pair, which is itself the evidence the signal is worth acting on: the alert fires on response traffic alone, with no crafted request. The rule summary states that the server leaks information via the X-AspNet-Version and X-AspNetMvc-Version response header fields, and the remediation is a server configuration change rather than a code change, meaning the fix is available wherever the platform supports suppressing the field. The Other Info names the attacker's use directly: the disclosed information can be used to exploit known vulnerabilities. That is why the class matters despite a Low rating. The information content is one version number, but it converts an open-ended search across all ASP.NET CVEs into a lookup against a version-keyed list. The hunting action is to inventory every host emitting a version-bearing header, confirm whether the value is a real version or a redacted constant, and where real, correlate against the advisory feed for that exact version rather than filing it as cosmetic.

- *Disproof:* If the header carries a pinned non-version value with no build number, or a gateway strips the field before it reaches the client, then no version oracle exists for the attacker.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/497.html); [zaproxy.org](https://www.zaproxy.org/docs/alerts/10061/)

**An AWS account where resource-explorer-2:ListResources is called from a long-lived access key before July 2025 was a cloud information disclosure with no CloudTrail record, because the call was classified as a data event logging only if the customer enabled data-event logging.**

Datadog Security Research reported that resource-explorer-2:ListResources previously did not log to AWS CloudTrail without additional configuration through data events, and that without this configuration customers were unlikely to detect the technique or know it was being used. The mechanism makes this a disclosure signal rather than a logging bug. Resource Explorer works through a service-linked role, AWSServiceRoleForResourceExplorer, that regularly enumerates AWS resources in the account and adds them to an index. An attacker with any valid credential queries that index instead of calling Describe APIs directly, so the traffic is attributed to the service role and carries none of the attacker's own calls. The inventory returned includes ARNs, resource types, owning account IDs and regions for every indexed resource. AWS reclassified the call as a management event on 15 July 2025 so it now logs by default; before that date absence of the log line proved nothing. The general lesson: for every cloud API, check whether its event class means an auditor sees it by default or only after deliberate configuration.

- *Disproof:* If the account already records resource-explorer-2 as a management event, or the calls originate from an ephemeral role session rather than a long-lived access key, then the enumeration leaves a log and the silence is genuine rather than structural.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/)

**A bare Unix epoch timestamp in an otherwise generic response is an information disclosure only when it can be aggregated across responses to expose an exploitable pattern, making aggregation the deciding test rather than presence.**

ZAP's timestamp-disclosure rule is classified Passive with CWE-497 and its summary is deliberately narrow: a timestamp was disclosed by the application or web server. The remediation guidance is the part worth internalising because it makes the signal conditional. Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns. That is the disproof test written by the tool authors. A single epoch value is near noise and says almost nothing about the system; the series carries the information. A build timestamp on every response across many hosts reveals a shared deploy window and therefore a fleet that restarts together. A timestamp inside a signed token or cache key reveals the secret rotation epoch. A timestamp differing per response by a fixed interval leaks the internal scheduler period. The hunting action is not to flag and move on: collect the timestamp across responses from the same host, plot the deltas, and escalate only when a repeating interval or cross-host shared window appears.

- *Disproof:* If each response carries a timestamp derived only from the moment of the request, or no second timestamp from the same source exists to correlate against, then there is nothing to aggregate and the disclosure does not materialise.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [zaproxy.org](https://www.zaproxy.org/docs/alerts/10096/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Any application on an EC2 instance can read instance metadata including IAM role credentials from the link-local address 169.254.169.254, and EKS pods by default can reach the worker node's metadata the same way.**

Datadog's Misconfiguration Spotlight states the exposure precisely: instance metadata is accessible to any application running on an EC2 instance via a link-local address, 169.254.169.254. The metadata is described as important information about each individual instance including the AMI ID, hostname and associated security groups, and in a security context, if an IAM role is associated with the instance, then IAM credentials for that role are available in the instance metadata. The attacker path is therefore generic: find any SSRF or RCE on the instance, then read metadata. A common technique for cloud attackers is to steal IAM credentials from instance metadata via server-side request forgery, and their guidance is to look for SSRF in web applications running on EC2 and, when found, access the instance metadata and steal IAM credentials; Mandiant had already identified a threat actor doing this with CVE-2021-21311. IMDSv2 is the control and it is specifically an information-disclosure control: session-oriented, requiring a token from a PUT request passed in a header, which blocks the blind SSRF a GET-based reader cannot satisfy. Adoption is the weak point, with as many as 93 percent of all EC2 instances not enforcing IMDSv2. The container variant matters separately because pods by default can reach the worker node metadata.

- *Disproof:* If the instance enforces IMDSv2 so a session token must be obtained by PUT before any read is honoured, and the token hop limit is left at default so intermediate proxies do not forward it, then a blind SSRF cannot retrieve credentials.
- *Evidence:* high_confidence — [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An information disclosure is confirmed by comparing the same request sent unauthenticated and with a valid session and by differencing responses across object identifiers: if a field the unauthenticated caller should not influence differs, the response content is the disclosure.**

CAPEC frames the underlying condition: by exploiting weaknesses in the design or configuration of the target and its communications, an adversary is able to get the target to reveal more information than intended, and the information retrieved may aid the adversary in making inferences about potential weaknesses. The word intended is what makes this a differential test rather than an inventory. The procedure is a baseline and a comparison. The baseline is the request sent with no credentials, captured byte for byte including status, headers and body length. The comparison is the identical request under a valid session, or with a single identifier changed. Three outcomes are distinguishable. Identical responses mean no session-dependent disclosure. A status change alone is an existence oracle, still a disclosure because the caller learned something they had no right to know. A body or header field populated in only one response is a direct disclosure of server-side data. The trap is diffing against an unrelated endpoint: two pages on the same application share headers, so a naive comparison attributes ordinary template output to the object under test. Vary one dimension per pair, hold the rest fixed, and record the baseline so later changes can be distinguished from output that was always there.

- *Disproof:* If the unauthenticated and authenticated responses are byte-identical, or the only difference is a session cookie or CSRF token carrying no server-side data, then no information crossed the authorisation boundary and there is no disclosure to validate.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [checkmarx.com](https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/); [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-acl/)

**A low-entropy disclosure such as a timestamp, build identifier or repeated internal hostname is promoted from finding to vulnerability only when values collected across multiple responses or hosts aggregate into a pattern that narrows an attacker's search space.**

The aggregation requirement is stated by the tool authors themselves. ZAP's remediation guidance for its timestamp-disclosure rule says to manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns. Both clauses matter. The first asks whether the individual value is itself sensitive, which for an epoch timestamp is usually no. The second asks whether the sequence is, which is sometimes decisively yes. Aggregation succeeds when a value is drawn from a small space. Build timestamps let an attacker restrict candidate advisories to versions released before the build date. A repeated internal hostname or staging subdomain turns guessing into a lookup against a candidate list. A monotonically increasing identifier discloses the record count of a table, which directly answers a question the caller had no right to ask. A constant delta between successive values leaks the internal scheduler or batching period. The validation procedure is to sample the same field from many responses and hosts, then ask two questions: is the value space small, and is the pattern stable across samples. Only when both are true does the item clear the bar, and the write-up should carry the collected series as evidence rather than the single instance that triggered it.

- *Disproof:* If each collected value is unique per request and no cross-response or cross-host relationship exists, then no aggregation is possible and the disclosure remains noise regardless of how many instances were sampled.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [zaproxy.org](https://www.zaproxy.org/docs/alerts/10096/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Coordinated scraping of a platform's public API surface, including public repositories, gists, followers and org memberships, all returning HTTP 200 with no failed-auth signal, is the platform working as designed and is a false positive for information disclosure unless the activity is shown to have crossed into private data.**

Datadog Security Research observed a sustained pattern of this and wrote the disproof conditions into their own analysis. A large share of GitHub's API surface is reachable without authentication: listing an organization's public repositories, walking a user's followers and following lists, enumerating gists, starred repos and org memberships, and running GraphQL queries against public objects all return data. Because these paths are public by design, requests produce HTTP 200 responses and generate no failed-auth signal, and an operator can build a detailed map of an organization, such as its public repositories, its members, who those members follow, and which projects they touch, entirely from public data. The traffic blends into normal API usage, and GitHub does not populate geolocation data for events on external resources, which limits attribution. Datadog tracked more than 50 ghost accounts, created two to five years earlier and left dormant before activation, using user agents like GitHub-Company-Scraper. None of that makes the platform vulnerable. The false-positive rule is narrow and checkable: no authentication boundary was crossed, so there is no disclosure. The escalation trigger is equally explicit, since the same activity escalated past public information enumeration, appearing to successfully clone private repositories; that converts a detection into a breach finding. Hunt the correlation fields rather than the volume: user agent, token type, source ASN, attempted actions.

- *Disproof:* If the activity is shown to have successfully cloned private repositories or used a compromised token to read non-public objects, then it crossed the design boundary and the finding is a real disclosure rather than a false positive.
- *Evidence:* high_confidence — [checkmarx.com](https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/); [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/)

**Reject a info_disclosure finding until it is distinguished from the adjacent behaviour this class also covers. "Where exposure measurement reports that more than 80 percent of OT control, power monitoring and IoT systems communicate over legacy insecure protocols such as BACnet and MODBUS, the disclosed asset and protocol inventory is what makes..." and "Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Where exposure measurement reports that more than 80 percent of OT control, power monitoring and IoT systems communicate over legacy insecure protocols such as BACnet and MODBUS, the disclosed asset and protocol inventory is what makes...

Adjacent behaviour that produces the same observable result: Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Disclosed SPN-bearing account names from directory enumeration are the" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [checkmarx.com](https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An attacker bypasses attribution of cloud enumeration by querying a service-linked-role-backed resource index rather than calling resource APIs directly, because the resulting requests are logged against the AWS service role and not against the compromised identity.**

The technique is described by Datadog as proxying enumeration activity through an AWS service, so that those API calls aren't traced back to the identity the threat actor compromised. AWS Resource Explorer is a resource search and discovery service that works using a service-linked role named AWSServiceRoleForResourceExplorer, which regularly enumerates AWS resources in the account and adds them to an index. From the offensive perspective attackers can avoid making direct API calls themselves: instead they query the index and launder their enumeration calls through the service, disassociating that activity from themselves. Invoked with no additional parameters, resource-explorer-2:ListResources returns the default view, which by default includes all resources currently indexed, each entry carrying ARN, OwningAccountId, Region, ResourceType, Service and LastReportedAt. That is a full account inventory from one call, and it is the same shape as any exposed-service inventory an attacker builds before choosing an entry point: once an attacker knows which services exist and are reachable, the choice of first foothold narrows to a small known-vulnerable set, which is exactly how exposed services became a primary initial-access route. AWS reclassified the call as a management event on 15 July 2025, closing the bypass for new accounts; the defensive replacements Datadog proposes are an SCP blocking the Resource Explorer service, and alerts when CreateIndex or ListResources is called from a long-lived access key, which is the only identity signal left once the call is attributed to the role.

- *Disproof:* If the account already logs resource-explorer-2 as a management event, or the enumeration is performed with the compromised key directly rather than through the service role's index, then the requests remain attributable to the identity and the laundering bypass does not apply.
- *Evidence:* high_confidence — [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/exposed-services-public-clouds/)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 7. Impact

_What is actually demonstrable, and what to stop claiming._

**Where exposure measurement reports that more than 80 percent of OT control, power monitoring and IoT systems communicate over legacy insecure protocols such as BACnet and MODBUS, the disclosed asset and protocol inventory is what makes physical disruption a reachable outcome rather than a theoretical one.**

Claroty's Team82 data centre research quantifies the chain rather than asserting it, over a data set of more than 750,000 assets. Its critical qualifier is that while it's rare that assets are directly connected to the internet, they are not inherently protected from cyberattacks, and direct connectivity is not always a prerequisite for compromise. The mechanism is proximity: attackers can often find success moving laterally after the compromise of an asset that is usually no more than one hop from an exposed CPS asset. Data center asset exposures are reached via indirect pathways into operational environments through interconnected IT systems, third-party remote access, remote management services, and trusted network relationships. The exposure profile follows: more than 80 percent of OT control systems, power monitoring and IoT systems communicate over legacy, insecure protocols such as BACnet and MODBUS, 88 percent of BMS communicate over insecure protocols with 40 percent containing outdated firmware, and 23 percent of IoT devices are vulnerable to known exploited vulnerabilities. Claroty's own Norwegian dam case shows the terminal outcome of this chain, where attackers compromised a weak password and manipulated valves, causing an increase in water discharge above the mandated minimum flow, undetected for four hours. The hunting use is to treat a disclosed OT asset inventory as a prioritisation input: the one-hop rule tells you which disclosed assets to trace forward to physical consequence.

- *Disproof:* If the disclosed inventory cannot be reached from the adversary's compromised asset, or the OT segment is segmented such that no path exists from IT to the affected devices, then the disclosure informs attack planning without enabling physical impact.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/158.html); [claroty.com](https://www.claroty.com/blog/data-center-exposures-and-the-pathways-putting-data-center-assets-at-risk)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
