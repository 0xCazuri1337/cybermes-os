# Single-publisher gap worklist

Generated: `2026-11-02T20:41:25Z` from `db/wks.db`.

The gate holds these items as `INSUFFICIENT_PUBLISHER_HOSTS`: after builder/static-hosting pages are excluded, every citation resolves to one publisher org. `db/sources.json` lists normative sources for the class; the candidates below are from a *different* org and are places to read, not evidence.

**Never paste a quote into the corpus unless `wks.verify_quotes.find_quote` accepts it against the live page.** Candidate presence is not promotion.

## Summary

- blocked items: **45**
- classes: **18**
- items with at least one candidate: **45**
- items without a candidate: **0**
- publisher-only + candidate (citation may close it): **40**
- blocker classes: `{'claim_and_disproof': 1, 'claim_repair': 4, 'publisher_only': 40}`

Only `publisher_only` items are citation-closable. `claim_repair`, `quote_repair`, `disproof_repair`, and mixed items need the named repair first; adding a second publisher around a broken claim would launder it.

## Classes

| Class | Blocked | Candidate orgs |
|---|---:|---|
| `ssrf` | 6 | mitre.org, owasp.org, portswigger.net |
| `xxe` | 5 | mitre.org, portswigger.net |
| `ad_acl_abuse` | 4 | microsoft.com, mitre.org |
| `info_disclosure` | 4 | mitre.org, owasp.org, portswigger.net |
| `prototype_pollution` | 4 | mitre.org, portswigger.net |
| `xss` | 4 | mitre.org, owasp.org |
| `host_header` | 3 | mitre.org, portswigger.net |
| `container_escape` | 2 | docker.com, mitre.org |
| `deser` | 2 | mitre.org, owasp.org, portswigger.net |
| `ssti` | 2 | mitre.org, portswigger.net |
| `supply_chain` | 2 | mitre.org, owasp.org, portswigger.net |
| `ad_delegation` | 1 | microsoft.com, mitre.org |
| `ad_enumeration` | 1 | rfc-editor.org |
| `ad_ldap` | 1 | mitre.org, rfc-editor.org |
| `adcs_abuse` | 1 | microsoft.com, mitre.org, rfc-editor.org |
| `rate_limit` | 1 | cloudflare.com, owasp.org |
| `service_enumeration` | 1 | microsoft.com, mitre.org |
| `subdomain_takeover` | 1 | mitre.org, owasp.org, portswigger.net |

## Detail

### `ssrf` — 6 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/918.html
- `owasp.org` [ACTIVE] cheatsheet https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/ssrf

**Items**

- `ssrf.1` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:cwe.mitre.org)']`
  - CWE-918 defines SSRF as a weakness where a web server receives a URL from an upstream component and retrieves its contents without sufficiently ensuring the request is sent to the expected destination.
- `ssrf.2` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - A classic SSRF signal is an application that fetches a user-supplied URL and returns its contents; attackers exploit trust relationships so that requests to localhost or internal IPs are granted access the attacker could never reach directly.
- `ssrf.3` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Blind SSRF is reliably detected using out-of-band (OAST) techniques: trigger an HTTP request to a domain the attacker controls and monitor for any inbound request from the target.
- `ssrf.4` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - SSRF filters are routinely bypassed using alternative IP representations of loopback, URL-encoding or case variation, open-redirect chains, credential embedding, URL fragments, and fully-qualified DNS hierarchy tricks.
- `ssrf.5` — **publisher_only**; counted orgs: `owasp.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:cheatsheetseries.owasp.org)']`
  - OWASP's SSRF prevention guidance mandates allowlist-first validation, with a canonical deny-list of loopback, RFC1918 private, link-local, multicast, AWS/GCP/Azure metadata, and IPv6 unique-local ranges; it also warns that domain allowlisting alone does not stop DNS rebinding.
- `ssrf.7` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:attack.mitre.org,ctid.mitre.org)']`
  - The Ivanti Connect Secure / Neurons chain demonstrates SSRF as a chain link: CVE-2023-46805 (authentication bypass) and CVE-2024-21887 (RCE) were followed by CVE-2024-21893, an SSRF vulnerability in the SAML component, which was used to bypass mitigations of the earlier two vulnerabilities by chaining with CVE-2024-21887.

### `xxe` — 5 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/611.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/xxe

**Items**

- `xxe.2` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Defining an external entity that references a local file, then embedding that entity inside a data value echoed back in the response, retrieves the file contents.
- `xxe.3` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Blind XXE, where the application does not reflect entity values in-band, can be exploited by hosting a malicious DTD and invoking it through a parameter entity to exfiltrate data out-of-band, or by triggering error messages that contain the data.
- `xxe.5` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Defenses that block ampersand-based entity references can be bypassed with XML parameter entities, which are declared with % and referenced with %; and are evaluated inside the DTD rather than as data values.
- `xxe.6` — **publisher_only**; counted orgs: `owasp.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:cheatsheetseries.owasp.org)']`
  - The most reliable remediation is to disable DTD processing and external entity resolution in every parser instance, and never parse untrusted XML with default settings.
- `xxe.7` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:cwe.mitre.org)']`
  - CWE-611 (XXE) and CWE-918 (SSRF) are closely related weaknesses that chain: XXE can be leveraged as an SSRF primitive, using the vulnerable parser to forge outbound requests against internal systems the attacker cannot reach directly.

### `ad_acl_abuse` — 4 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1222/001/

**Items**

- `ad_acl_abuse.dcsync_rights` — **claim_repair**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)', 'OFF_CLASS_TOPIC']`
  - A principal holding both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain object can perform DCSync to dump all domain hashes including krbtgt.
- `ad_acl_abuse.genericall_user` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)']`
  - GenericAll over a user object lets an attacker reset the password, set an SPN for targeted Kerberoasting, or write msDS-KeyCredentialLink for shadow credentials, gaining control of that account.
- `ad_acl_abuse.writedacl_selfgrant` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)']`
  - WriteDACL on any object lets an attacker grant themselves GenericAll on that object, then abuse it as if they already held full control.
- `ad_acl_abuse.writeowner_takeover` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)']`
  - WriteOwner on an object lets an attacker take ownership of it, then grant themselves WriteDACL and finally GenericAll, achieving full control.

### `info_disclosure` — 4 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] cwe https://cwe.mitre.org/data/definitions/200.html
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/information-disclosure

**Items**

- `info_disclosure.3` — **claim_repair**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)', 'OFF_CLASS_TOPIC']`
  - Session IDs and credentials exposed via URLs, logs, and Referer headers.
- `info_disclosure.4` — **claim_repair**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)', 'OFF_CLASS_TOPIC']`
  - Password reset poisoning via Host header rewrites reset links.
- `info_disclosure.5` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Source code disclosure via backup files, temp files, and .git metadata
- `info_disclosure.impact.ht_but_if_they_work_and_they_are_disc` — **publisher_only**; counted orgs: `mitre.org`; builder host(s) ignored: `kathan19.gitbook.io`
  - gate: `['BUILDER_PAGE_NOT_PUBLISHER(kathan19.gitbook.io)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:capec.mitre.org)']`
  - An endpoint surfaced by web page source review is a triage lead whose severity depends on what that endpoint exposes, ranging from an authentication bypass to a sensitive information leak.

### `prototype_pollution` — 4 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/1321.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/prototype-pollution

**Items**

- `prototype-pollution.002` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Prototype pollution sources include the URL query string and fragment (hash) via keys such as __proto__[prop] or __proto__.prop, JSON input parsed by JSON.parse (whose keys are arbitrary strings), and web messages; any of these can write to a prototype when merged recursively.
- `prototype-pollution.003` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - If an application strips the literal '__proto__' key from input, the '__proto__' accessor can be avoided entirely by using 'constructor.prototype': for any object created by a constructor, myObject.constructor.prototype resolves to the same prototype as myObject.__proto__, so keys 'constructor' and 'prototype' provide an alternative route to pollute Object.prototype (or String.prototype/Array.prototype).
- `prototype-pollution.004` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - A sanitizer that removes only the first occurrence of the literal '__proto__' substring is bypassable: a key such as '__pro__proto__to__' survives a single strip and resolves to '__proto__' when the merge follows the dotted name, polluting the prototype.
- `prototype-pollution.005` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:cwe.mitre.org)']`
  - Prototype pollution causes denial of service and can break authentication or authorization checks: overriding pre-defined prototype attributes such as hasOwnProperty, toString, or valueOf can break code that depends on them, and overriding an attribute with an incompatible type can crash the application.

### `xss` — 4 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/79.html
- `owasp.org` [ACTIVE] cheatsheet https://owasp.org/www-community/attacks/xss/

**Items**

- `xss.auto.04` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - DOM XSS reads attacker-controlled data in JavaScript (location.hash, location.search, location.href, document.referrer, document.write, innerHTML, eval, setTimeout or a string argument) and executes it against the serving origin.
- `xss.bypass.01` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - A sanitizer can be bypassed with mutation XSS: markup that is safe under the sanitizer's parser is re-parsed by the browser into an executable form.
- `xss.bypass.02` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Content Security Policy can be defeated when the vulnerable sink is an svg+xml response that ignores the script-src policy, a JSONP endpoint on a whitelisted domain, or a base tag that re-points script sources.
- `xss.chain.01` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - A reflected XSS fused with an unkeyed cache input becomes persistent stored-equivalent XSS at CDN scale: the payload is injected through an unkeyed parameter and served to every visitor until the cache TTL.

### `host_header` — 3 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/644.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/host-header

**Items**

- `host_header.bypass.02` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Sending duplicate Host headers, or mixing an absolute-form request target with a Host header, can produce a divergence between the front-end router and the application logic, allowing a payload to pass validation while reaching a different code path.
- `host_header.impact.01` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:owasp.github.io)']`
  - Without Host validation, an attacker can dispatch requests to the first (internal) name-based virtual host on the server, gaining access to applications that were not intended to be externally reachable.
- `host_header.pattern.01` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - Some web servers drop or canonicalise the port (or the entire value) before validation, so an attacker can inject a payload through a non-numeric port or an ambiguous value while the request still reaches the intended application.

### `container_escape` — 2 blocked

**Candidate sources** (different org from the item's current citations):

- `docker.com` [ACTIVE] docs https://docs.docker.com/engine/security/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1611/

**Items**

- `container_escape.cgroups_release_agent` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)']`
  - The cgroups release_agent technique escapes a container by writing a release_agent script that executes on the host when the cgroup empties.
- `container_escape.docker_socket` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)']`
  - A mounted Docker socket inside a container lets an attacker spawn a privileged container with the host filesystem mounted, gaining host root.

### `deser` — 2 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/502.html
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/deserialization

**Items**

- `deser.4` — **publisher_only**; counted orgs: `portswigger.net`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:portswigger.net)']`
  - PHP's phar:// stream wrapper deserializes a PHAR's serialized manifest metadata implicitly when any filesystem operation is performed on the stream, so a polyglot file masquerading as an image can achieve RCE through an innocuous method such as file_exists().
- `deser.6` — **publisher_only**; counted orgs: `owasp.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:community.owasp.org)']`
  - Deserialization can be driven to denial of service by constructing recursive object graphs that never terminate, or by requesting arrays of Integer.MAX_VALUE size, which can exhaust CPU or memory before elements are even read.

### `ssti` — 2 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/1336.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/server-side-template-injection

**Items**

- `ssti.evidence.a_dns_callback_received_after_an_ssti_payloa` — **publisher_only**; counted orgs: `projectdiscovery.io`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:projectdiscovery.io)', 'CROSS_CLASS_BOILERPLATE(2 quotes shared with other classes and none is class-specific)']`
  - A convincing observation for this class is: The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.
- `ssti.test.a_dns_callback_received_after_an_ssti_payload_is` — **publisher_only**; counted orgs: `projectdiscovery.io`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:projectdiscovery.io)', 'CROSS_CLASS_BOILERPLATE(2 quotes shared with other classes and none is class-specific)']`
  - To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener.

### `supply_chain` — 2 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/1104.html
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/dependencies

**Items**

- `supply_chain.auto.b.2` — **publisher_only**; counted orgs: `securelist.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:securelist.com)']`
  - Typosquatting: a package name one or two characters off from a popular dependency bypasses exact-name allowlisting because resolution is by string match, not semantic equivalence.
- `supply_chain.signal.ci-egress-credential-exposure` — **claim_repair**; counted orgs: `paloaltonetworks.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:unit42.paloaltonetworks.com)', 'OFF_CLASS_TOPIC']`
  - A CI runner able to reach arbitrary network destinations will hand its inherited credentials to whatever a build step contacts, so build-time egress restriction is an access-control boundary rather than a hardening nicety.

### `ad_delegation` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1134/003/

**Items**

- `ad_delegation.prerequisite.delegation-abuse-requires-in-forest-delegation-config` — **publisher_only**; counted orgs: `hackthebox.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:academy.hackthebox.com)']`
  - Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.

### `ad_enumeration` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `rfc-editor.org` [ACTIVE] standard https://www.rfc-editor.org/rfc/rfc4511.html

**Items**

- `ad_enumeration.fp_rule.admin_enumeration_command_is_dual_use` — **publisher_only**; counted orgs: `mitre.org`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:attack.mitre.org)', 'CROSS_CLASS_BOILERPLATE(1 quotes shared with other classes and none is class-specific)']`
  - A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.

### `ad_ldap` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] cwe https://cwe.mitre.org/data/definitions/90.html
- `rfc-editor.org` [ACTIVE] standard https://www.rfc-editor.org/rfc/rfc4511.html

**Items**

- `ad_ldap.nmap_scripts` — **publisher_only**; counted orgs: `tryhackme.com`; builder host(s) ignored: `h3ll-ka1ser.gitbook.io`
  - gate: `['BUILDER_PAGE_NOT_PUBLISHER(h3ll-ka1ser.gitbook.io)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:tryhackme.com)']`
  - Nmap LDAP scripts enumerate naming contexts, users, and groups from a domain controller on ports 389 and 636.

### `adcs_abuse` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1649/
- `rfc-editor.org` [ACTIVE] standard https://www.rfc-editor.org/rfc/rfc5280.html

**Items**

- `adcs_abuse.auto.t.b2acc3f1` — **claim_and_disproof**; counted orgs: `nccgroup.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:nccgroup.com)', 'BOILERPLATE_DISPROOF', 'OFF_CLASS_TOPIC']`
  - With StrongCertificateBindingEnforcement configured as 0, an account with GenericWrite permissions can be exploited to compromise any other account.

### `rate_limit` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `cloudflare.com` [ACTIVE] docs https://developers.cloudflare.com/waf/rate-limiting-rules/
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

**Items**

- `rate_limit.bypass.2` — **publisher_only**; counted orgs: `github.com`; builder host(s) ignored: `havbay.gitbook.io`
  - gate: `['BUILDER_PAGE_NOT_PUBLISHER(havbay.gitbook.io)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com)']`
  - Batching or parameter pollution compresses many logical operations into one physical request, bypassing per-request and per-operation rate limits.

### `service_enumeration` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `microsoft.com` [ACTIVE] docs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
- `mitre.org` [ACTIVE] taxonomy https://attack.mitre.org/techniques/T1046/

**Items**

- `service_enumeration.banner_grabbing` — **publisher_only**; counted orgs: `github.com`
  - gate: `['INSUFFICIENT_PUBLISHER_HOSTS(1<2:github.com,sammyha.github.io)']`
  - Banner grabbing connects to a service and reads its initial response, revealing service name, version, and OS hints.

### `subdomain_takeover` — 1 blocked

**Candidate sources** (different org from the item's current citations):

- `mitre.org` [ACTIVE] taxonomy https://cwe.mitre.org/data/definitions/404.html
- `owasp.org` [ACTIVE] cheatsheet https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
- `portswigger.net` [ACTIVE] cheatsheet https://portswigger.net/web-security/misconfiguration

**Items**

- `subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence` — **publisher_only**; counted orgs: `cloudflare.com`
  - gate: `['INSUFFICIENT_SOURCES(1<2)', 'INSUFFICIENT_PUBLISHER_HOSTS(1<2:developers.cloudflare.com)']`
  - Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.
