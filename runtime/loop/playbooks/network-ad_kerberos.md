# Hunt card — ad_kerberos

6 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## ad_kerberos.technique.kerberoast_rc4_tgs_offline_crack

**Claim.** A Kerberos service ticket whose SPN is issued to an account with no interactive login (a service principal) is an offline password-cracking oracle when the KDC still protects it with RC4, because the ticket's encrypted part is keyed on the account password hash.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## ad_kerberos.signal.tgs-fanout-to-many-unique-spns

**Claim.** A single host receiving TGS-REP responses for numerous unique SPNs inside a short window is an early observable for Kerberoasting but is identical to legitimate service-ticket traffic.

**Procedure — Race / TOCTOU attempt** (shapes: race_condition)

1. Identify the check and the use as TWO separate operations, and measure the gap between them.
2. Fire many parallel attempts (tens to hundreds) so at least one lands inside the window.
3. Vary ONLY the timing; the payload and session stay fixed.
4. Report a rate, not a single success: N successes in M attempts both proves the window and tells the reader whether it is practical to exploit.

**Record:** attempts, successes, success rate, window size if measurable

## ad_kerberos.technique.spn_set_is_the_roastable_precondition

**Claim.** An AD account with a service principal name set is requestable by any authenticated domain principal, and the returned ticket is encrypted with the account's own long-term key, so the SPN inventory is the precondition that makes offline key recovery a single request away.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## ad_kerberos.technique.asrep_roast_preauth_disabled

**Claim.** A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## ad_kerberos.technique.krbtgt_hash_ticket_forgery

**Claim.** Possession of the KRBTGT account password hash is sufficient to forge arbitrary Kerberos ticket-granting tickets for any principal in the forest, because KRBTGT is the key that signs and encrypts every TGT in that domain.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

## ad_kerberos.technique.kerberoasting_targets_service_tickets_for_accounts_with_a

**Claim.** Kerberoasting targets service tickets for accounts with a pre-authentication setting that permits it, and the returned ticket is cracked offline for the account password.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions
