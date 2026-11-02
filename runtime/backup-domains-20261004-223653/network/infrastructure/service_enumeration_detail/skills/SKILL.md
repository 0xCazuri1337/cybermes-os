---
name: service_enumeration_detail-hunting
description: Use when hunting Service-Specific Configuration Assessment in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Service-Specific Configuration Assessment — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-16 · OWASP —
> evidence: 7 items, 5 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

**Also called:** service configuration, configuration assessment, service hardening, protocol configuration, misconfigured service


## Techniques (what to change)

- Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## False-positive rules (when to reject it)

- A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.  _(merged 1 duplicate row(s))_
  - **Disproof:** The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "As a result, it is imperative that organizations implement exposure ma" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Evidence requirements

- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure) states the full boundary.
  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>


## Hunt procedure

1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
4. Record raw request and response pairs verbatim, including headers, before you interpret anything.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/infrastructure/service_enumeration_detail/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
