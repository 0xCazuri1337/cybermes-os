# Hunt card — smb

4 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## smb.validation.differential_signing_state_bounds_the_relay_ceiling

**Claim.** A relay finding is bounded by the negotiated signing state, so the validation that separates a real relay path from a non-finding is a differential test of the same request with and without a valid signature, not the mere presence of an SMB listener.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## smb.technique.authenticated_smb_is_execution_channel

**Claim.** SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## smb.test.when_the_target_enforces_smb_signing_the_relay_s

**Claim.** To decide this case, observe: Discard when the tester reported that authentication succeeded but no session could be used: without the shared session key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## smb.technique.anonymous_or_guest_access_to_an_smb_share_and_the_enumera

**Claim.** Anonymous or guest access to an SMB share, and the enumeration that reveals it, is the usual route to credentials or a file drop on a Windows target.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)
