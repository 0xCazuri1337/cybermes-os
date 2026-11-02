# Quote-support audit

Generated: `2026-10-28T15:58:56Z` from `db/wks.db`.

This is an audit of **whether the quoted span discusses the item's claim**. It is not a truth oracle. `LABEL_ONLY` and `TEMPLATE` are enforced by the gate; `NO_LEXICAL_SUPPORT` is a review queue because paraphrase is common.

## Summary

- items with quoted sources: **1321**
- quoted sources: **2866**
- items with a label-only quote: **0** `{}`
- items with the generated CVE template: **0** `{}`
- items with no lexical/class support in any quoted source: **28** `{'high_confidence': 25, 'under_review': 3}`

## No lexical/class support by class

| Class | Items |
|---|---:|
| `bizlogic` | 5 |
| `crlf` | 4 |
| `info_disclosure` | 4 |
| `ldap` | 4 |
| `race` | 2 |
| `service_enumeration_detail` | 2 |
| `supply_chain` | 2 |
| `idor` | 1 |
| `jwt` | 1 |
| `misconfig` | 1 |
| `open_redirect` | 1 |
| `smb` | 1 |

## Label-only quotes

None.

## Generated CVE template claims

None.

## No lexical/class support (review queue)

- `bizlogic.evidence.a_logic_flaw_reported_by_an_automated_scanne` [high_confidence] — A convincing observation for this class is: What legitimately does not clear the bar is a response difference, a status code, or a parameter a scanner rated unusual, with no invariant shown to be violated.
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/840.html
    - quote: They can be difficult to find automatically, since they typically involve legitimate use of the application's functionality.
  - `portswigger.net` https://portswigger.net/web-security/logic-flaws
    - quote: This makes them difficult to detect using automated vulnerability scanners.
- `bizlogic.evidence.a_price_discount_or_total_that_the_server_ec` [high_confidence] — A convincing observation for this class is: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulat
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/840.html
    - quote: They can be difficult to find automatically, since they typically involve legitimate use of the application's functionality.
  - `portswigger.net` https://portswigger.net/web-security/race-conditions
    - quote: They occur when websites process requests concurrently without adequate safeguards.
- `bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass` [high_confidence] — A price, discount, or total that the server echoes back from the client request body without independently recomputing it is a finding only when the echoed figure is the figure that is charged, otherwise it is a display-only reflection of u
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/840.html
    - quote: They can be difficult to find automatically, since they typically involve legitimate use of the application's functionality.
  - `portswigger.net` https://portswigger.net/web-security/race-conditions
    - quote: They occur when websites process requests concurrently without adequate safeguards.
- `bizlogic.test.a_concurrent_request_test_showing_a_duplicated_r` [under_review] — To decide this case, observe: Discard the race-condition report when the double effect appeared in a single interleaved pair and does not recur over dozens of repetitions, because one anomalous outcome is indistinguishable from scheduler no
  - `httpwg.org` https://httpwg.org/specs/rfc9110.html
    - quote: The 405 (Method Not Allowed) status code indicates that the method received in the request-line is known by the origin server but not supported by the target resource.
  - `projectdiscovery.io` https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught
    - quote: Neo read the code, identified the missing business rule that refunds shouldn't exceed original transaction amount, built a proof-of-concept
- `bizlogic.test.a_price_discount_or_total_that_the_server_echoes` [high_confidence] — To decide this case, observe: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/840.html
    - quote: They can be difficult to find automatically, since they typically involve legitimate use of the application's functionality.
  - `portswigger.net` https://portswigger.net/web-security/race-conditions
    - quote: They occur when websites process requests concurrently without adequate safeguards.
- `crlf.bypass.percent-encoded-newline-defeats-single-line-anchor` [high_confidence] — A validator that rejects literal CR/LF but anchors with ^...$ without DOTALL still passes a percent-encoded %0d%0a payload that a downstream decoder turns back into a real line terminator.
  - `github.blog` https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/
    - quote: unexpected newline characters ( \n ) may be introduced in order to bypass brittle validation. Normalize or encode the input
  - `security.googleblog.com` https://security.googleblog.com/2011/05/website-security-for-webmasters.html
    - quote: you can specify any URL as an image source, regardless of its content type. It can be an HTML page, a JavaScript file
- `crlf.evidence.this_looks_like_crlf_injection_a_0d_0a_paylo` [high_confidence] — A convincing observation for this class is: The separating observation is WHERE in the response those bytes are.
  - `crowdstrike.com` https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/
    - quote: The code then searches for an attacker-specified substring in the message and inserts the inject after it.
  - `security.googleblog.com` https://security.googleblog.com/2011/05/website-security-for-webmasters.html
    - quote: But is it truly harmless? If I decode the percent-encoded characters, I get:
- `crlf.fp.percent-encoded-crlf-reflected-in-body` [high_confidence] — This LOOKS like CRLF injection (a %0d%0a payload comes back verbatim in the response) but is actually inert text in an HTML body, separated by the bytes landing after the header/body boundary rather than inside a header value.
  - `crowdstrike.com` https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/
    - quote: The code then searches for an attacker-specified substring in the message and inserts the inject after it.
  - `security.googleblog.com` https://security.googleblog.com/2011/05/website-security-for-webmasters.html
    - quote: But is it truly harmless? If I decode the percent-encoded characters, I get:
- `crlf.prerequisite.untrusted-data-reaches-response-header` [high_confidence] — CRLF/response-splitting requires an untrusted value to reach a response header value or a response body position where the HTTP serializer emits a line terminator.
  - `blog.cloudflare.com` https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora
    - quote: the smuggled request could inject headers and its URL into a subsequent valid request sent on the same connection
  - `github.blog` https://github.blog/security/web-application-security/encoding-escaping-untrusted-data-prevent-injection-attacks/
    - quote: unexpected newline characters ( \n ) may be introduced in order to bypass brittle validation. Normalize or encode the input
- `idor.signal.gap_sequences_and_leaked_foreign_ids` [high_confidence] — Gaps in otherwise sequential id sequences, and object responses that embed foreign owner ids, are recon signals that a collection is enumerable and unfiltered.
  - `portswigger.net` https://portswigger.net/web-security/graphql
    - quote: By querying the ID of the missing product, we can get its details, even though it is not listed on the shop
  - `wstg.owasp.org` https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL/
    - quote: every user (even unauthenticated) can gain access to the auth tokens of every veterinarian listed in the database
- `info_disclosure.bypass.service_linked_role_enum_laundering` [high_confidence] — An attacker bypasses attribution of cloud enumeration by querying a service-linked-role-backed resource index rather than calling resource APIs directly, because the resulting requests are logged against the AWS service role and not against
  - `securitylabs.datadoghq.com` https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/
    - quote: attackers can avoid making direct API calls themselves
  - `unit42.paloaltonetworks.com` https://unit42.paloaltonetworks.com/exposed-services-public-clouds/
    - quote: Notorious ransomware groups such as REvil and Mespinoza are known to exploit exposed services to gain initial access to victims’ environments.
- `info_disclosure.evidence.an_information_disclosure_is_confirmed_by_co` [high_confidence] — A convincing observation for this class is: Identical responses mean no session-dependent disclosure.
  - `capec.mitre.org` https://capec.mitre.org/data/definitions/118.html
    - quote: an adversary is able to get the target to reveal more information than intended
  - `checkmarx.com` https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/
    - quote: The attackers scraped customer data, including personally identifiable information (PII), via an unsecured API endpoint publicly available on the internet.
- `info_disclosure.evidence.reject_a_info_disclosure_finding_until_it_is` [under_review] — A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user
  - `capec.mitre.org` https://capec.mitre.org/data/definitions/118.html
    - quote: an adversary is able to get the target to reveal more information than intended
  - `checkmarx.com` https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/
    - quote: organizations can identify otherwise undocumented endpoints (known as shadow APIs)
- `info_disclosure.test.a_low_entropy_disclosure_such_as_a_timestamp_bui` [high_confidence] — To decide this case, observe: The validation procedure is to sample the same field from many responses and hosts, then ask two questions: is the value space small, and is the pattern stable across samples.
  - `capec.mitre.org` https://capec.mitre.org/data/definitions/118.html
    - quote: Information retrieved may aid the adversary in making inferences about potential weaknesses, vulnerabilities, or techniques that assist the adversary's objectives.
  - `zaproxy.org` https://www.zaproxy.org/docs/alerts/10096/
    - quote: Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.
- `jwt.fp_rule.key_headers_present_is_not_a_vuln` [high_confidence] — The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
  - `cheatsheetseries.owasp.org` https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
    - quote: These parameters have legitimate uses, so the distinction is anchoring rather than avoidance.
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/347.html
    - quote: Gain Privileges or Assume Identity; Modify Application Data; Execute Unauthorized Code or Commands
- `ldap.fp_rule.an_empty_result_on_an_injection_string_means_no_bug_not_a_failed_attack` [high_confidence] — A rejected or empty-result response to an LDAP injection payload is the expected outcome of a correctly escaped implementation and must be reported as a negative test rather than as evidence of a partially working attack.
  - `openldap.org` https://www.openldap.org/doc/admin24/security.html
    - quote: Note : Disabling the anonymous bind mechanism does not prevent anonymous access to the directory.
  - `rfc-editor.org` https://www.rfc-editor.org/rfc/rfc4511.txt
    - quote: Servers MUST NOT return errors if attribute descriptions or matching rule ids are not recognized, assertion values are invalid, or the assertion syntax is not supported.
- `ldap.signal.result-set-widens-and-directory-attributes-appear` [high_confidence] — A widened or non-empty result set for a filter that should have matched nothing, carrying directory attributes the application never renders on a normal miss, is the observable signature of a request-controlled filter structure.
  - `blackhillsinfosec.com` https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning
    - quote: because we know BloodHound, AdExplorer, ADFind, and other LDAP enumerators read the UAC value for discovered objects
  - `trustedsec.com` https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer
    - quote: In the LDAP world, objects are identified by their distinguished name, or DN.
- `ldap.validation.prove_filter_injection_with_a_presence_filter_returning_extra_entries` [high_confidence] — The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather t
  - `openldap.org` https://www.openldap.org/doc/admin24/security.html
    - quote: Anonymous bind mechanism is enabled by default, but can be disabled by specifying " disallow bind_anon " in slapd.conf (5).
  - `rfc-editor.org` https://www.rfc-editor.org/rfc/rfc4511.txt
    - quote: present [7] AttributeDescription,
- `ldap.validation.prove_the_injection_by_contrasting_a_widened_filter_against_a_same_shape_escaped_filter` [high_confidence] — Injection is proven only when a wildcard-bearing filter and a byte-identical filter whose metacharacters have been escaped as \XX produce measurably different result sets against the same directory, which isolates filter structure as the on
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/90.html
    - quote: The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream c
  - `rfc-editor.org` https://www.rfc-editor.org/rfc/rfc4515.html
    - quote: SubstringFilter ::= SEQUENCE { type AttributeDescription, -- initial and final can occur at most once substrings SEQUENCE SIZE (1..MAX) OF substring CHOICE { initial [0] AssertionValue, any [1] AssertionV
- `misconfig.fp_rule.a_version_banner_alone_is_information_disclosure_not_rce` [under_review] — A full product and version banner in a response header is an information-disclosure finding of low severity, not an exploit, because the header alone confers no capability unless a specific matching vulnerability is shown to be reachable.
  - `docs.docker.com` https://docs.docker.com/engine/security/
    - quote: if you instrument Docker from a web server to provision containers through an API, you should be even more careful than usual with parameter checking
  - `httpd.apache.org` https://httpd.apache.org/docs/2.4/mod/core.html
    - quote: Server sends ( e.g. ): Server: Apache/2.4.2
- `open_redirect.evidence.the_meaningful_observation_is_the_unvalidated_destination_after_login_not_before_it` [high_confidence] — The consequential open-redirect evidence is the post-authentication hop — the redirect that fires after a real login or token grant, not a bare redirect on an unauthenticated entry point, because the pre-auth redirect carries no session whi
  - `developers.google.com` https://developers.google.com/identity/protocols/oauth2/web-server
    - quote: If this value doesn't match an authorized URI,
  - `expressjs.com` https://expressjs.com/en/advanced/best-practice-security.html
    - quote: An application must validate that it supports redirecting to the incoming URL to avoid sending users to malicious links such as phishing websites, among other risks.
- `race.test.reject_the_finding_if_your_requests_were_seriali` [high_confidence] — To decide this case, observe: Put a unique nonce in each request and confirm all 20 appear in responses from the same origin with distinct upstream timings.
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/367.html
    - quote: If you cannot perform operations atomically and you must share access to the resource between multiple processes
  - `owasp.org` https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
    - quote: there are discrepancies in the way incoming requests are processed by servers
- `race.validation.break_business_invariant` [high_confidence] — Prove the race by breaking an invariant single-threaded use cannot reach: negative balance, two votes from one account, more items shipped than paid for.
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/367.html
    - quote: The product may perform invalid actions when the resource is in an unexpected state.
  - `portswigger.net` https://portswigger.net/web-security/logic-flaws/examples
    - quote: This functionality will almost certainly check whether the sender has sufficient funds before completing the transfer
- `service_enumeration_detail.evidence.a_tcp_banner_that_reveals_the_service_name_a` [high_confidence] — A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.
  - `capec.mitre.org` https://capec.mitre.org/data/definitions/300.html
    - quote: Typical Severity Low Relationships This table shows the other attack patterns and high level categories that are related to this attack pattern.
  - `claroty.com` https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems
    - quote: In cybersecurity, the term exposure refers to the state of being susceptible to potential cyber attacks due to vulnerabilities or weaknesses
- `service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure` [high_confidence] — A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when th
  - `capec.mitre.org` https://capec.mitre.org/data/definitions/300.html
    - quote: Typical Severity Low Relationships This table shows the other attack patterns and high level categories that are related to this attack pattern.
  - `claroty.com` https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems
    - quote: In cybersecurity, the term exposure refers to the state of being susceptible to potential cyber attacks due to vulnerabilities or weaknesses
- `smb.fp_rule.netsh-portproxy-and-lotw-smb-are-built-in-features` [high_confidence] — SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.
  - `learn.microsoft.com` https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy
    - quote: interface portproxy add v4tov4 Adds a proxy rule to listen on an IPv4 address and port, forwarding incoming TCP connections to another IPv4 address and port.
  - `securelist.com` https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/
    - quote: portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445
- `supply_chain.test.artifact_carries_a_live_credential_requires_the_secret_to_work_from_inside_the_published_artifact` [high_confidence] — A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/798.html
    - quote: The product contains hard-coded credentials, such as a password or cryptographic key.
  - `docs.github.com` https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
    - quote: Note that there is risk to this approach even if you trust the author, because a tag can be moved or deleted if a bad actor gains access to the repository storing the action.
- `supply_chain.test.post_install_execution_requires_the_lifecycle_script_to_run_and_produce_an_observable_effect` [high_confidence] — An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory
  - `cwe.mitre.org` https://cwe.mitre.org/data/definitions/506.html
    - quote: The product contains code that appears to be malicious in nature.
  - `docs.npmjs.com` https://docs.npmjs.com/cli/v11/using-npm/scripts
    - quote: Scripts from dependencies can be run with npm explore -- npm run .
