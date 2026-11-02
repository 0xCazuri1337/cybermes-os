# clickjacking: observe, exercise, confirm

> goal: `Establish, exercise and confirm a clickjacking condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for clickjacking. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a clickjacking condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The false positive: a scanner or a reviewer sees `<iframe src="/app/widget">` on an authenticated page and files clickjacking. It is benign when the framed document is SAME-ORIGIN with the embedder...

**Requires:** an authorised target with a reachable surface for clickjacking, and permission to record responses

**Backed by:** `clickjacking.fp.same-origin-iframe-embed`

**This step fails if:** Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.

### 2. Exercise it against the target and capture the raw request and response: The impact of a frameable state-changing page is that a foreign origin can force an authenticated user's action and capture a per-page token, turning one redressed click into privilege escalation.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `clickjacking.impact.cross-origin-forced-action-and-token-theft`

**This step fails if:** Disproof is a state-change requirement: the framed route takes no state-changing action on a single click, or requires a second factor the click alone cannot satisfy, or the token on the page is not reachable from the framed context. Also disproof: the framed response sets `SameSite` on its session cookie such that the cross-site POST carries no session at all, so there is no authenticated victim to act as. Any of these collapses the impact to nuisance.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `clickjacking.validation.differential_render_proves_the_overlay_not_just_the_missing_header`

**This step fails if:** The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
