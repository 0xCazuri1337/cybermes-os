# segmentation_analysis: observe, exercise, confirm

> goal: `Establish, exercise and confirm a segmentation_analysis condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for segmentation_analysis. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a segmentation_analysis condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The measurable form of network segmentation is whether packets with private source or destination addresses cross a boundary. RFC 1918 requires that routing information about private networks not be...

**Requires:** an authorised target with a reachable surface for segmentation_analysis, and permission to record responses

**Backed by:** `segmentation_analysis.technique.private_addressing_marks_the_boundary`

**This step fails if:** If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.

### 2. Exercise it against the target and capture the raw request and response: A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `segmentation_analysis.fp_rule.baseline-must-enumerate-known-infrastructure`

**This step fails if:** Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `segmentation_analysis.signal.no-single-universal-rdp-indicator-set`

**This step fails if:** Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.
