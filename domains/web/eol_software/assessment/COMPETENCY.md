# Methodology — End-of-life and unpatchable platform

> Derived from 9 verified items. Regenerate with `python -m wks.methodgen --class eol_software --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A platform or version past end of life that receives no fixes, on an internet-reachable surface. Distinct from version disclosure: the defect is that no future fix is possible.

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral movement, and remediation guidance makes each asset's internet exposure an explicit evaluation axis.**

An unpatchable host that is not reachable from the internet is a different finding from one that is. Edge devices sit at the network perimeter, so a single vulnerability on them that has no fix converts directly into an entry point: initial access, lateral movement, operational disruption and data exfiltration. CISA's own remediation language for catalogued exploited vulnerabilities makes the same distinction operationally, placing the burden on the stakeholder to evaluate each asset's internet exposure rather than treating exposure as implicit in the entry.

- *Disproof:* Refuted if the same unpatchable device is demonstrated to be unreachable from the public internet, for example by a verified negative result from an external scan of the full port range plus a confirmed internal-only routing path, which would move the finding from this class to an internal exposure record.
- *Evidence:* high_confidence — [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

**Vendor end of support is the exact moment at which future remediation becomes impossible: after that date every later vulnerability is still disclosed and assigned a CVE, but no fix is ever produced, so the disclosure record grows while the remediation surface stays fixed.**

The defect is not the vulnerability that revealed the product; it is the lifecycle state. On one side of the end-of-life date a fix is a normal vendor deliverable. On the other side the same vulnerability class produces disclosure without remedy, permanently and predictably. A finding raised against such a product is therefore valid even if the specific CVE tests clean: the unpatchability is the reportable condition, not the exploitability of the sample.

- *Disproof:* Refuted when the vendor resumes security support for the affected version line, or publishes a backported fix for a post-end-of-life CVE, which would show the end-of-support date did not in fact close the remediation path.
- *Evidence:* high_confidence — [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or a long gap since release.**

A version string alone cannot tell a hunter whether a product is unpatchable, and routine vulnerability scanners do not raise the condition: end-of-life dates do not trigger a scanner alert, do not open a ticket and do not appear on a sprint board. The observable that does distinguish the condition is a statement in the authoritative entry that no update exists, because the remediation text itself is the lifecycle assertion. Reading that text is the cheap triage step that separates this finding from ordinary version disclosure.

- *Disproof:* Refuted if the disconnect or no-update instruction is shown to have been issued for a reason other than lifecycle state, for example a temporary withdrawal pending a legal or safety hold that the vendor later reversed with a supported build.
- *Evidence:* high_confidence — [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print); [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts)

**The authoritative signal for whether a product is unpatchable is the vendor's own support lifecycle statement for that specific model and version, and it is not obtainable from any published government list of unsupported devices.**

Proving unpatchability per asset requires a lifecycle answer from the vendor of the exact device, and that is where the determination has to be made. Government does maintain lists of unsupported edge hardware internally, but they are not published, which means a hunter cannot cite a list and must instead resolve support status from vendor lifecycle documentation. Versions are also declared end of life years ahead, so the date is public and dated rather than inferred from age.

- *Disproof:* Refuted if a published, authoritative list of end-of-service devices with per-model support status becomes available from a government publisher, since that would displace the per-vendor lifecycle lookup as the primary determination path.
- *Evidence:* high_confidence — [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When a known-exploited vulnerability lands on a product that is already past its end-of-life date, the required action is disconnect or replacement, because the vendor will never ship a fix and the entry has no patch path at all.**

CISA's KEV catalog carries entries whose remediation text is not a patch instruction but a disconnection instruction, because the affected product is past end of life and no fix is coming. The catalog therefore functions as a machine-readable list of unpatchable exposures: a hunter matching a target's product and version against a KEV row whose action is 'disconnect' has found a defect that no future update can remediate, only migration can. Remediation is migration, not patching.

- *Disproof:* Refuted when the vendor's own security advisory for the same CVE publishes a fixed build that is still downloadable and supported, or when CISA later replaces the disconnect action on that KEV row with an 'apply update' action, which would show a patch path existed after all.
- *Evidence:* high_confidence — [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print); [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts)

**Use of unsupported or end-of-life software is filed as a dangerous practice rather than a routine hygiene gap, and the observed exploitation of such devices is by state-linked actors who target them precisely because no vendor updates arrive.**

CISA files 'use of unsupported (or end-of-life) software' in its catalog of Bad Practices alongside default passwords and single-factor administrative access, calling it dangerous and, for internet-accessible technology, especially egregious. The operational half of the same observation is that nation-state-linked actors are already exploiting these devices in the wild, so an unpatchable edge box is an occupied position rather than a latent one.

- *Disproof:* Refuted if the named device class is shown to still receive vendor firmware or security patches under a paid or contractual support arrangement, or if a government attestation attributes exploitation of that exact device class to a commodity crimeware operator with no state linkage, which would weaken the severity without refuting the practice classification.
- *Evidence:* high_confidence — [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

**Where mitigations are unavailable, the mandated action for an unpatchable product is to discontinue or decommission it on a fixed deadline, so an unpatchable exposure is closed by removal from the network rather than by any future patch.**

Remediation guidance for catalogued exploited vulnerabilities carries an explicit branch for the case where mitigation does not exist: the instruction is to discontinue use of the product. The same shape appears in the operational directive for unsupported edge hardware, which pairs an immediate update-to-supported requirement with a dated decommission requirement and an inventory step in between. The hunter's action is unchanged by these schedules: the exposure is removed, so there is no patch to wait for.

- *Disproof:* Refuted if the vendor supplies a compensating control that removes the exploited condition without updating the product, for example disabling the affected service or protocol entirely, which would satisfy the guidance without decommissioning the platform.
- *Evidence:* high_confidence — [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral...

Adjacent behaviour that produces the same observable result: The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The recognition signal for an unpatchable product is a stated absence " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

**An old product is not an unpatchable one: the test that separates the two is vendor support termination, verified by confirming the product no longer receives security fixes from its vendor, not the age of the version or the length of time since its last release.**

Age alone is not a defect and must not be filed as one. The falsifiable test is lifecycle state: does this product still receive security fixes from its vendor, and has the vendor published an end of life announcement covering it. A dated end-of-life announcement plus the absence of security fixes is what makes the finding, and it is also what an assessor checks, which is why an annual review to confirm continued vendor security fixes is a control requirement rather than a formality. Without that vendor-side fact, a version banner is only an age observation.

- *Disproof:* Refuted if the vendor is shown to have issued a security fix, or an extended-support contract covering the exact version, within the period the finding calls unpatchable, since either fact restores a remediation path and demotes the item to ordinary version disclosure.
- *Evidence:* high_confidence — [endoflife.ai](https://endoflife.ai/article-eol-calendar-alerts); [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
