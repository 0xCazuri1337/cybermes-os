# Single-publisher gap worklist

Generated: `2026-10-28T15:58:56Z` from `db/wks.db`.

The gate holds these items as `INSUFFICIENT_PUBLISHER_HOSTS`: after builder/static-hosting pages are excluded, every citation resolves to one publisher org. `db/sources.json` lists normative sources for the class; the candidates below are from a *different* org and are places to read, not evidence.

**Never paste a quote into the corpus unless `wks.verify_quotes.find_quote` accepts it against the live page.** Candidate presence is not promotion.

## Summary

- blocked items: **12**
- classes: **8**
- items with at least one candidate: **12**
- items without a candidate: **0**
- publisher-only + candidate (citation may close it): **9**
- blocker classes: `{'claim_and_disproof': 1, 'claim_repair': 1, 'disproof_repair': 1, 'publisher_only': 9}`

Only `publisher_only` items are citation-closable. `claim_repair`, `quote_repair`, `disproof_repair`, and mixed items need the named repair first; adding a second publisher around a broken claim would launder it.

## Classes

| Class | Blocked | Candidate orgs |
|---|---:|---|
| `ad_enumeration` | 4 | mitre.org, rfc-editor.org |
| `ssti` | 2 | mitre.org, portswigger.net |
| `ad_delegation` | 1 | microsoft.com, mitre.org |
| `adcs_abuse` | 1 | microsoft.com, mitre.org, rfc-editor.org |
| `info_disclosure` | 1 | owasp.org, portswigger.net |
| `pass_the_hash` | 1 | microsoft.com, mitre.org |
| `subdomain_takeover` | 1 | mitre.org, owasp.org |
| `supply_chain` | 1 | mitre.org, owasp.org |

## Detail

### `ad_enumeration` — 4 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1087/002/
- `rfc-editor.org` [ACTIVE] standard https://www.rfc-editor.org/rfc/rfc4511.html

**Items**

- `ad_enumeration.evidence.a_single_instance_of_a_native_enumeration_co` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:attack.mitre.org)']`
  - A convincing observation for this class is: The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance.
- `ad_enumeration.evidence.ad_enumeration_performed_with_native_windows` — **publisher_only**; counted orgs: `ired.team`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:ired.team)']`
  - A convincing observation for this class is: The observable that triggers this false positive is AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool, filed either as malicious module use or as a detection gap because no command-line alert fired.
- `ad_enumeration.evidence.reject_a_ad_enumeration_finding_until_it_is` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:attack.mitre.org)']`
  - A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.
- `ad_enumeration.fp_rule.admin_enumeration_command_is_dual_use` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:attack.mitre.org)']`
  - A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.

### `ssti` — 2 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/1336.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/server-side-template-injection

**Items**

- `ssti.evidence.a_dns_callback_received_after_an_ssti_payloa` — **publisher_only**; counted orgs: `projectdiscovery.io`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:projectdiscovery.io)']`
  - A convincing observation for this class is: The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.
- `ssti.test.a_dns_callback_received_after_an_ssti_payload_is` — **publisher_only**; counted orgs: `projectdiscovery.io`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:projectdiscovery.io)']`
  - To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener.

### `ad_delegation` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1134/003/

**Items**

- `ad_delegation.prerequisite.delegation-abuse-requires-in-forest-delegation-config` — **publisher_only**; counted orgs: `hackthebox.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:academy.hackthebox.com)']`
  - Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.

### `adcs_abuse` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1649/
- `rfc-editor.org` [ACTIVE] standard https://www.rfc-editor.org/rfc/rfc5280.html

**Items**

- `adcs_abuse.auto.t.b2acc3f1` — **claim_and_disproof**; counted orgs: `nccgroup.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:nccgroup.com)', 'BOILERPLATE_DISPROOF', 'OFF_CLASS_TOPIC']`
  - With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.

### `info_disclosure` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/information-disclosure

**Items**

- `info_disclosure.impact.ht_but_if_they_work_and_they_are_disc` — **publisher_only**; counted orgs: `mitre.org`; builder host(s) ignored: `kathan19.gitbook.io`
  - gate: `['BUILDER_PAGE_NOT_PUBLISHER(kathan19.gitbook.io)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:capec.mitre.org)']`
  - An endpoint surfaced by web page source review is a triage lead whose severity depends on what that endpoint exposes, ranging from an authentication bypass to a sensitive information leak.

### `pass_the_hash` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1550/002/

**Items**

- `pass_the_hash.auto.t.b2dcb935` — **disproof_repair**; counted orgs: `marcfredericgomez.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:blog.marcfredericgomez.com)', 'BOILERPLATE_DISPROOF']`
  - The KRBTGT object’s hash allows arbitrary TGTs to be forged.

### `subdomain_takeover` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/404.html
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html

**Items**

- `subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence` — **publisher_only**; counted orgs: `cloudflare.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:developers.cloudflare.com)']`
  - Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.

### `supply_chain` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/1104.html
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

**Items**

- `supply_chain.signal.ci-egress-credential-exposure` — **claim_repair**; counted orgs: `paloaltonetworks.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:unit42.paloaltonetworks.com)', 'OFF_CLASS_TOPIC']`
  - A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.
