# HUNT runbook — ad_trust_abuse

**9 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py ad_trust_abuse network`).

Sources of steps: 0 item-authored, 9 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [ad_trust_abuse.technique.kerberoast_across_a_parent_child_trust_escalates_to_the_parent](#ad-trust-abuse-technique-kerberoast-across-a-parent-child-trust-escalates-to-the-parent) — Filesystem sink confirmation
- [ad_trust_abuse.test.a_trust_object_that_exists_in_configuration_but](#ad-trust-abuse-test-a-trust-object-that-exists-in-configuration-but) — Claim verification (no mechanical template matched)
- [ad_trust_abuse.variant.unconstrained_delegation_across_a_forest_trust_leaks_a_parent_tgt](#ad-trust-abuse-variant-unconstrained-delegation-across-a-forest-trust-leaks-a-parent-tgt) — Claim verification (no mechanical template matched)
- [ad_trust_abuse.signal.abnormal_domain_reconnaissance_spanning_kerberos_ldap_and_dns](#ad-trust-abuse-signal-abnormal-domain-reconnaissance-spanning-kerberos-ldap-and-dns) — Filesystem sink confirmation
- [ad_trust_abuse.technique.trust_rewrite_forges_cross_forest_token](#ad-trust-abuse-technique-trust-rewrite-forges-cross-forest-token) — Filesystem sink confirmation
- [ad_trust_abuse.auto.t.f2b6f2ca](#ad-trust-abuse-auto-t-f2b6f2ca) — Filesystem sink confirmation
- [ad_trust_abuse.auto.t.627ba518](#ad-trust-abuse-auto-t-627ba518) — Filesystem sink confirmation
- [ad_trust_abuse.auto.t.2c52cf26](#ad-trust-abuse-auto-t-2c52cf26) — Filesystem sink confirmation
- [ad_trust_abuse.auto.t.a1aa60bc](#ad-trust-abuse-auto-t-a1aa60bc) — Filesystem sink confirmation

<a id="ad-trust-abuse-technique-kerberoast-across-a-parent-child-trust-escalates-to-the-parent"></a>

## ad_trust_abuse.technique.kerberoast_across_a_parent_child_trust_escalates_to_the_parent

**Claim.** An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, race_condition; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Race / TOCTOU attempt* — Identify the check and the use as TWO separate operations, and measure the gap between them.

<a id="ad-trust-abuse-test-a-trust-object-that-exists-in-configuration-but"></a>

## ad_trust_abuse.test.a_trust_object_that_exists_in_configuration_but

**Claim.** To decide this case, observe: This does not make it harmless - a configured trust is available to anyone who later compromises the partner domain, and dormant trust objects are exactly what gets forgotten during incident response - so the correct output is a hygiene finding on an unused trust, not an abuse finding.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="ad-trust-abuse-variant-unconstrained-delegation-across-a-forest-trust-leaks-a-parent-tgt"></a>

## ad_trust_abuse.variant.unconstrained_delegation_across_a_forest_trust_leaks_a_parent_tgt

**Claim.** Unconstrained delegation configured on a machine or service principal in a trusted forest lets an attacker who compromises that host capture a TGT for any user who authenticates to it, including across the trust.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="ad-trust-abuse-signal-abnormal-domain-reconnaissance-spanning-kerberos-ldap-and-dns"></a>

## ad_trust_abuse.signal.abnormal_domain_reconnaissance_spanning_kerberos_ldap_and_dns

**Claim.** Reconnaissance that walks trust relationships shows up as LDAP volume against trust and configuration objects, Kerberos user enumeration, and DNS zone transfer requests from hosts that are not DNS servers.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, blind_confirmation; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — oob: **do** make the sink call back to a host you control; **observe** the callback, with timestamp and token.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Blind / out-of-band confirmation* — Establish that your out-of-band channel works AT ALL with a known true positive before drawing any conclusion from its absence.

<a id="ad-trust-abuse-technique-trust-rewrite-forges-cross-forest-token"></a>

## ad_trust_abuse.technique.trust_rewrite_forges_cross_forest_token

**Claim.** Changing a domain's trust configuration to include an adversary-controlled domain lets an identity from that domain forge access tokens that victim-domain resources will accept.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="ad-trust-abuse-auto-t-f2b6f2ca"></a>

## ad_trust_abuse.auto.t.f2b6f2ca

**Claim.** As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="ad-trust-abuse-auto-t-627ba518"></a>

## ad_trust_abuse.auto.t.627ba518

**Claim.** Hence, as penetration testers we must have a deep understanding of the ins and outs of AD, its complexities, intricacies, and the many ways it can be misconfigured or native features can be abused.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="ad-trust-abuse-auto-t-2c52cf26"></a>

## ad_trust_abuse.auto.t.2c52cf26

**Claim.** While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="ad-trust-abuse-auto-t-a1aa60bc"></a>

## ad_trust_abuse.auto.t.a1aa60bc

**Claim.** We may also identify trust relationships with other forests and compromising a partner forest may grant us access that we need to compromise our current forest through any number of attacks.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
