# misconfig: observe, exercise, confirm

> goal: `Establish, exercise and confirm a misconfig condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for misconfig. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a misconfig condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation is an unauthenticated administrative interface on a device in the field, which is usually filed as authentication removed or a backdoor web shell installed. On a large class of...

**Requires:** an authorised target with a reachable surface for misconfig, and permission to record responses

**Backed by:** `misconfig.fp_rule.factory_device_without_portal_password_is_default_not_tampering`

**This step fails if:** The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.

### 2. Exercise it against the target and capture the raw request and response: They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `misconfig.auto.t.d06bbf83`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `misconfig.auto.t.b00b60cd`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
