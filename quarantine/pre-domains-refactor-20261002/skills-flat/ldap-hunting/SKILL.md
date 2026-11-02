---
name: ldap-hunting
description: Use when hunting LDAP / XPath / NoSQL-Style Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# LDAP / XPath / NoSQL-Style Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 90 · OWASP A03:2021
> evidence: 7 items, 7 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

A filter or path expression is built from attacker input, changing the query structure.

**Also called:** ldap injection, xpath injection, orm injection


## Recon signals (where to look)

- A widened or non-empty result set for a filter that should have matched nothing, carrying directory attributes the application never renders on a normal miss, is the observable signature of a request-controlled filter structure.
  - **Disproof:** Show that the application's own empty-result path already returns a populated template, or that the attributes in the response are rendered by the frontend from data it fetched on a separate call. Then the widened response is application behaviour rather than directory-side filter evaluation.
  - Sources: <https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer> · <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>

## Techniques (what to change)

- Where a web-facing application performs an LDAP bind over TLS to a domain controller, the reachable post-injection step is relay of that bind to the DC's LDAPS listener, whose precondition is an absent or strippable client-side message-integrity check.
  - **Disproof:** Show that the application's LDAPS bind presents a channel binding token and that the target DC enforces validation, so a relayed bind is rejected at the TLS layer. Then the bind is not relayable and the post-injection step does not exist.
  - Sources: <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>

## Validation bar (how to prove it)

- An LDAP injection test is only meaningful after confirming which directory attribute the request-controlled value lands in, because the returned attribute set of a benign query reveals the server-side mapping without any injection being required.
  - **Disproof:** Show that the benign response's attribute set is constant regardless of the submitted value and contains no directory identifier, DN, or SID, while the server demonstrably issues an LDAP search as visible in LDAP diagnostic logging. Then the request value does not enter the filter and no injection test on that field is valid.
  - Sources: <https://trustedsec.com/blog/kerberos-with-titanis> · <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>

## False-positive rules (when to reject it)

- A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.
  - **Disproof:** Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>

## Impact framing

- Where LDAP signing is not required and channel binding is at its default, a network position between an application and its domain controller can obtain usable bind credential material, making the impact credential theft rather than enumeration.
  - **Disproof:** Show the domain controllers enforce LDAP signing and channel binding at their enforcing settings with auditing in place, so an intercepted bind is rejected at the DC rather than yielding credential material. Then the impact is bounded and the critical severity rating is wrong.
  - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>

## Defence bypasses

- A domain controller left at the default channel binding policy accepts a bind that carries no channel binding token at all, so relay protection is off unless the policy has been explicitly raised - and only the Always setting actually blocks the bind.
  - **Disproof:** Show the domain controllers have channel binding token requirements set to Always with logging enabled, and that a bind carrying no channel binding token is rejected by the DC rather than merely logged. Then relay protection is active and the bypass does not exist on that target.
  - Sources: <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>

## Chaining opportunities

- LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access into a credential path.
  - **Disproof:** Show the CA has HTTP enrollment disabled, or request disposition set to pending or manual approval, so no certificate can be issued unattended. Then LDAP reachability stops at read access and the chain does not close.
  - Sources: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc> · <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3>

---
Full class document: `skills/Web/ldap/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap`
