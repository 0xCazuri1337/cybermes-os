# otp: observe, exercise, confirm

> goal: `Establish, exercise and confirm a otp condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for otp. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a otp condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A verification endpoint that accepts the same one-time value twice for one nonce can be replayed by anyone who observed that value during its short validity window.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: 5.1.4.1 Single-Factor OTP Authenticators Single-factor OTP authenticators contain two persistent values. The first is a symmetric key that persists for the device's lifetime. The second is a nonce...

**Requires:** an authorised target with a reachable surface for otp, and permission to record responses

**Backed by:** `otp.w11.bypass.b8d06a59`

**This step fails if:** Submit the identical code twice for the same login attempt: if the second submission is refused with a used-code or expired-code response, the value is single-use and no replay window exists.

### 2. Exercise it against the target and capture the raw request and response: An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `otp.w11.bypass.e5a73d26`

**This step fails if:** Force the second-factor call to fail (block the endpoint, starve it) and log in: if the session is still established, the flow fails open and the downgrade is real.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Reject a otp finding until it is distinguished from the adjacent behaviour this class also covers. "A reverse-proxy phishing relay placed between the user and the real login service passes traffic through untouched, so the one-time code and the resulting...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `otp.fp_rule.auto.derived`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An authentication flow whose second factor fails open, or which falls " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
