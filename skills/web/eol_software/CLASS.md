<!-- GENERATED from db/wks.db — do not edit -->
# End-of-life and unpatchable platform

## Definition

A platform or version past end of life that receives no fixes, on an internet-reachable surface. Distinct from version disclosure: the defect is that no future fix is possible.

- **CWE:** None
- **OWASP:** None
- **Surface:** infra

Canonical home for `eol_software`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral movement, and remediation guidance makes each asset's internet exposure an explicit evaluation axis.**

An unpatchable host that is not reachable from the internet is a different finding from one that is. Edge devices sit at the network perimeter, so a single vulnerability on them that has no fix converts directly into an entry point: initial access, lateral movement, operational disruption and data exfiltration. CISA's own remediation language for catalogued exploited vulnerabilities makes the same distinction operationally, placing the burden on the stakeholder to evaluate each asset's internet exposure rather than treating exposure as implicit in the entry.

*Disproof:* Refuted if the same unpatchable device is demonstrated to be unreachable from the public internet, for example by a verified negative result from an external scan of the full port range plus a confirmed internal-only routing path, which would move the finding from this class to an internal exposure record.

**Vendor end of support is the exact moment at which future remediation becomes impossible: after that date every later vulnerability is still disclosed and assigned a CVE, but no fix is ever produced, so the disclosure record grows while the remediation surface stays fixed.**

The defect is not the vulnerability that revealed the product; it is the lifecycle state. On one side of the end-of-life date a fix is a normal vendor deliverable. On the other side the same vulnerability class produces disclosure without remedy, permanently and predictably. A finding raised against such a product is therefore valid even if the specific CVE tests clean: the unpatchability is the reportable condition, not the exploitability of the sample.

*Disproof:* Refuted when the vendor resumes security support for the affected version line, or publishes a backported fix for a post-end-of-life CVE, which would show the end-of-support date did not in fact close the remediation path.

## Attack Surface

Surface: **infra**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An internet-facing host past its product's end-of-support date keeps completing TLS handshakes on the certificate it already holds for exactly as long as that certificate's Not After date allows, because holding a certificate valid past expiry requires someone to re-issue it and nobody does that once the vendor has stopped supporting the product, so a successful handshake proves reachability and says nothing about whether a patch path exists.**

Read the leaf certificate's validity dates off the target and compare Not After with the vendor's end-of-support date. The mechanism is that certificate validity is bounded by an explicit date pair: the CA baseline requirements define the validity period as the period from notBefore through notAfter inclusive and define the expiry date as the Not After value that closes it, so a publicly trusted certificate cannot be issued with an open-ended lifetime and the window an unmaintained host can serve in is fixed at issuance, independently of the product's support state. Keeping that window open is an action somebody must take, which is why an asset past end of support eventually stops validating. Concretely: probe the host, capture the served chain, record notBefore and notAfter for the leaf, and note the product version the certificate is fronting. If notAfter is still in the future the host is inside its own validity window and no vendor action is required for it to keep answering; if notAfter has passed, validation fails and the asset is offline whatever the remediation record claims. A leaf whose notBefore is later than the end-of-support date is the one observation that shows an external party is still maintaining the host, and that observation must be resolved before the asset is filed as unpatchable.

*Disproof:* Refuted when the served leaf certificate's notBefore is later than the product's end-of-support date and re-issuance is attributable to an identified party that is demonstrably still shipping signed updates to the host, since that establishes a live remediation path and shows the certificate dates cannot separate maintained assets from abandoned ones.

**The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or a long gap since release.**

A version string alone cannot tell a hunter whether a product is unpatchable, and routine vulnerability scanners do not raise the condition: end-of-life dates do not trigger a scanner alert, do not open a ticket and do not appear on a sprint board. The observable that does distinguish the condition is a statement in the authoritative entry that no update exists, because the remediation text itself is the lifecycle assertion. Reading that text is the cheap triage step that separates this finding from ordinary version disclosure.

*Disproof:* Refuted if the disconnect or no-update instruction is shown to have been issued for a reason other than lifecycle state, for example a temporary withdrawal pending a legal or safety hold that the vendor later reversed with a supported build.

**The authoritative signal for whether a product is unpatchable is the vendor's own support lifecycle statement for that specific model and version, and it is not obtainable from any published government list of unsupported devices.**

Proving unpatchability per asset requires a lifecycle answer from the vendor of the exact device, and that is where the determination has to be made. Government does maintain lists of unsupported edge hardware internally, but they are not published, which means a hunter cannot cite a list and must instead resolve support status from vendor lifecycle documentation. Versions are also declared end of life years ahead, so the date is public and dated rather than inferred from age.

*Disproof:* Refuted if a published, authoritative list of end-of-service devices with per-model support status becomes available from a government publisher, since that would displace the per-vendor lifecycle lookup as the primary determination path.

## Exploitation

**Where mitigations are unavailable, the mandated action for an unpatchable product is to discontinue or decommission it on a fixed deadline, so an unpatchable exposure is closed by removal from the network rather than by any future patch.**

Remediation guidance for catalogued exploited vulnerabilities carries an explicit branch for the case where mitigation does not exist: the instruction is to discontinue use of the product. The same shape appears in the operational directive for unsupported edge hardware, which pairs an immediate update-to-supported requirement with a dated decommission requirement and an inventory step in between. The hunter's action is unchanged by these schedules: the exposure is removed, so there is no patch to wait for.

*Disproof:* Refuted if the vendor supplies a compensating control that removes the exploited condition without updating the product, for example disabling the affected service or protocol entirely, which would satisfy the guidance without decommissioning the platform.

**When a known-exploited vulnerability lands on a product that is already past its end-of-life date, the required action is disconnect or replacement, because the vendor will never ship a fix and the entry has no patch path at all.**

CISA's KEV catalog carries entries whose remediation text is not a patch instruction but a disconnection instruction, because the affected product is past end of life and no fix is coming. The catalog therefore functions as a machine-readable list of unpatchable exposures: a hunter matching a target's product and version against a KEV row whose action is 'disconnect' has found a defect that no future update can remediate, only migration can. Remediation is migration, not patching.

*Disproof:* Refuted when the vendor's own security advisory for the same CVE publishes a fixed build that is still downloadable and supported, or when CISA later replaces the disconnect action on that KEV row with an 'apply update' action, which would show a patch path existed after all.

**Use of unsupported or end-of-life software is filed as a dangerous practice rather than a routine hygiene gap, and the observed exploitation of such devices is by state-linked actors who target them precisely because no vendor updates arrive.**

CISA files 'use of unsupported (or end-of-life) software' in its catalog of Bad Practices alongside default passwords and single-factor administrative access, calling it dangerous and, for internet-accessible technology, especially egregious. The operational half of the same observation is that nation-state-linked actors are already exploiting these devices in the wild, so an unpatchable edge box is an occupied position rather than a latent one.

*Disproof:* Refuted if the named device class is shown to still receive vendor firmware or security patches under a paid or contractual support arrangement, or if a government attestation attributes exploitation of that exact device class to a commodity crimeware operator with no state linkage, which would weaken the severity without refuting the practice classification.

## Variations

**An internet-facing application whose third-party component comes from an abandoned upstream project can never receive a fix for a CVE assigned after the abandonment, because no maintainer exists to accept and ship the patch, so the unpatchable condition is inherited from the dependency and survives every patch-management cycle applied to the application itself.**

Resolve every third-party component in the stack back to its upstream project and check whether that project still maintains it before treating the host as patchable. The mechanism is the absence of a maintainer, not the age of the code: CWE-1104 records that a product relying on components which are not actively supported or maintained by the original developer makes it difficult or impossible to fix significant bugs and vulnerabilities, and its own observed examples are components that reached end-of-life years before the CVE was assigned to the product that shipped them. On a reachable surface the check is concrete: for each component, find the upstream repository or distribution channel, probe its release history, compare the last release or commit date against the CVE's publication date, and record whether anything was published afterwards. Where nothing has been released since the CVE, the only remediation is replacement or a maintained fork, and OWASP's guidance for that case is a virtual patch that monitors or detects the issue rather than a vendor update that will never exist. The differential is the component's own upstream activity against the host application's own patch cadence: an application can be fully patched while shipping a dependency no one maintains.

*Disproof:* Refuted when the upstream project has since shipped a release that fixes the specific CVE, or when the deployment consumes a maintained downstream fork maintained by the original developer or a trusted proxy for that developer, since either fact restores an accepting maintainer and a real patch path and demotes the asset to ordinary component patching.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.eol_software.auto.01` — eol_software: observe, exercise, confirm (goal: `Establish, exercise and confirm a eol_software condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral...

Adjacent behaviour that produces the same observable result: The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The recognition signal for an unpatchable product is a stated absence " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**An old product is not an unpatchable one: the test that separates the two is vendor support termination, verified by confirming the product no longer receives security fixes from its vendor, not the age of the version or the length of time since its last release.**

Age alone is not a defect and must not be filed as one. The falsifiable test is lifecycle state: does this product still receive security fixes from its vendor, and has the vendor published an end of life announcement covering it. A dated end-of-life announcement plus the absence of security fixes is what makes the finding, and it is also what an assessor checks, which is why an annual review to confirm continued vendor security fixes is a control requirement rather than a formality. Without that vendor-side fact, a version banner is only an age observation.

*Disproof:* Refuted if the vendor is shown to have issued a security fix, or an extended-support contract covering the exact version, within the period the finding calls unpatchable, since either fact restores a remediation path and demotes the item to ordinary version disclosure.

## Validation

**An asset on a release line whose last phase carrying security updates has already ended is unpatchable even while the same product name is still supported, because support end is published per release line and per servicing channel rather than per product, so a non-LTS line or a build past its own end-of-servicing date has no patch path that the product-level date would wrongly suggest still exists.**

Resolve support state against the exact release line the asset reports, never against the product family name. Microsoft's own lifecycle definitions separate the point at which a specific version, feature update or servicing channel stops receiving quality OR security updates from the product's end of support, and its fixed policy keeps security updates flowing through a dated Extended Support phase, so a build that has passed its own servicing date stops receiving fixes while the product it belongs to is still supported. Oracle publishes the same per-line split for Java SE: the support roadmap gives every line its own Premier, Extended and Sustaining columns, and marks Extended Support 'Not Available' for the non-LTS feature lines while the LTS lines carry dated extended windows. Test on the target: probe the reported product, version and build string, look up that exact line in the vendor's own roadmap rather than the product entry, and verify whether any dated security-update window remains for it after the CVE's disclosure date. Where the row shows no extended or sustaining window, no fix will ever be issued for that asset no matter what the product-level support statement says. The differential that decides the case is the target's line against the vendor's per-line row, not the product name against a single end-of-support date.

*Disproof:* Refuted when the vendor's lifecycle documentation shows a single support-end date for the product that applies to every release line and servicing channel regardless of LTS designation or service pack, for example one date and no per-line rows, since that would remove the per-line boundary and make the product-level end date the only unpatchability test.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cabforum.org** (docs)
  - <https://cabforum.org/working-groups/server/baseline-requirements/requirements/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>
- **cisa.gov** (taxonomy)
  - <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
  - <https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/1104.html>
- **endoflife.ai** (docs)
  - <https://endoflife.ai/article-eol-calendar-alerts>
- **federalnewsnetwork.com** (writeup)
  - <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/lifecycle/definitions>
- **oracle.com** (docs)
  - <https://www.oracle.com/java/technologies/java-se-support-roadmap.html>
- **owasp.org** (taxonomy)
  - <https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
