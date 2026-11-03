# ad_ntlm: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ad_ntlm condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ad_ntlm. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ad_ntlm condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation is a single outbound SMB connect from a workstation to an external IP followed by an NTLM negotiate/challenge/authenticate exchange, which is what coercion looks like: a specially...

**Requires:** an authorised target with a reachable surface for ad_ntlm, and permission to record responses

**Backed by:** `ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft`

**This step fails if:** The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.

### 2. Exercise it against the target and capture the raw request and response: An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ad_ntlm.technique.ntlm_relay_authenticated_session_reuse`

**This step fails if:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ad_ntlm.prerequisite.ntlm-is-a-routine-protocol-before-it-is-a-finding`

**This step fails if:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
