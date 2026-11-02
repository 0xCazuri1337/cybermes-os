# Hunt card — exposed_rmm

2 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## exposed_rmm.test.a_legitimately_installed_rmm_agent_on_a_host_is

**Claim.** To decide this case, observe: Discard when the report rests on the tool being present and running: the joint advisory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## exposed_rmm.technique.rmm_inherits_the_operator_session

**Claim.** Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions
