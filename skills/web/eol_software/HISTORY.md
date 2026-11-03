# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 05:19 — 1 diff lines
- items: 9 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
(initial generation, 2026-10-03)
```

## 2026-10-04 00:43 — 77 diff lines
- items: 9 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- eol_software@current
+++ eol_software@new
@@ -18,42 +18,57 @@
 
 ## Prerequisites (do not start without these)
 
-- Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral movement, and remediation guidance makes each asset's internet exposure an explicit evaluation axis.
+- Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral movement, and remediation guidance makes each asset's internet exposure an explicit evaluation axis.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the same unpatchable device is demonstrated to be unreachable from the public internet, for example by a verified negative result from an external scan of the full port range plus a confirmed internal-only routing path, which would move the finding from this class to an internal exposure record.
   - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
-- Vendor end of support is the exact moment at which future remediation becomes impossible: after that date every later vulnerability is still disclosed and assigned a CVE, but no fix is ever produced, so the disclosure record grows while the remediation surface stays fixed.
+- Vendor end of support is the exact moment at which future remediation becomes impossible: after that date every later vulnerability is still disclosed and assigned a CVE, but no fix is ever produced, so the disclosure record grows while the remediation surface stays fixed.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the vendor resumes security support for the affected version line, or publishes a backported fix for a post-end-of-life CVE, which would show the end-of-support date did not in fact close the remediation path.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
 
 ## Recon signals (where to look)
 
-- The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or a long gap since release.
+- The authoritative signal for whether a product is unpatchable is the vendor's own support lifecycle statement for that specific model and version, and it is not obtainable from any published government list of unsupported devices.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if a published, authoritative list of end-of-service devices with per-model support status becomes available from a government publisher, since that would displace the per-vendor lifecycle lookup as the primary determination path.
+  - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
+- The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or a long gap since release.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the disconnect or no-update instruction is shown to have been issued for a reason other than lifecycle state, for example a temporary withdrawal pending a legal or safety hold that the vendor later reversed with a supported build.
   - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print> · <https://endoflife.ai/article-eol-calendar-alerts>
-- The authoritative signal for whether a product is unpatchable is the vendor's own support lifecycle statement for that specific model and version, and it is not obtainable from any published government list of unsupported devices.
-  - **Disproof:** Refuted if a published, authoritative list of end-of-service devices with per-model support status becomes available from a government publisher, since that would displace the per-vendor lifecycle lookup as the primary determination path.
-  - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
 
 ## Techniques (what to change)
 
-- Where mitigations are unavailable, the mandated action for an unpatchable product is to discontinue or decommission it on a fixed deadline, so an unpatchable exposure is closed by removal from the network rather than by any future patch.
+- Use of unsupported or end-of-life software is filed as a dangerous practice rather than a routine hygiene gap, and the observed exploitation of such devices is by state-linked actors who target them precisely because no vendor updates arrive.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the named device class is shown to still receive vendor firmware or security patches under a paid or contractual support arrangement, or if a government attestation attributes exploitation of that exact device class to a commodity crimeware operator with no state linkage, which would weaken the severity without refuting the practice classification.
+  - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
+- When a known-exploited vulnerability lands on a product that is already past its end-of-life date, the required action is disconnect or replacement, because the vendor will never ship a fix and the entry has no patch path at all.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the vendor's own security advisory for the same CVE publishes a fixed build that is still downloadable and supported, or when CISA later replaces the disconnect action on that KEV row with an 'apply update' action, which would show a patch path existed after all.
+  - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print> · <https://endoflife.ai/article-eol-calendar-alerts>
+- Where mitigations are unavailable, the mandated action for an unpatchable product is to discontinue or decommission it on a fixed deadline, so an unpatchable exposure is closed by removal from the network rather than by any future patch.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the vendor supplies a compensating control that removes the exploited condition without updating the product, for example disabling the affected service or protocol entirely, which would satisfy the guidance without decommissioning the platform.
   - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
-- When a known-exploited vulnerability lands on a product that is already past its end-of-life date, the required action is disconnect or replacement, because the vendor will never ship a fix and the entry has no patch path at all.
-  - **Disproof:** Refuted when the vendor's own security advisory for the same CVE publishes a fixed build that is still downloadable and supported, or when CISA later replaces the disconnect action on that KEV row with an 'apply update' action, which would show a patch path existed after all.
-  - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print> · <https://endoflife.ai/article-eol-calendar-alerts>
-- Use of unsupported or end-of-life software is filed as a dangerous practice rather than a routine hygiene gap, and the observed exploitation of such devices is by state-linked actors who target them precisely because no vendor updates arrive.
-  - **Disproof:** Refuted if the named device class is shown to still receive vendor firmware or security patches under a paid or contractual support arrangement, or if a government attestation attributes exploitation of that exact device class to a commodity crimeware operator with no state linkage, which would weaken the severity without refuting the practice classification.
-  - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
 
 ## False-positive rules (when to reject it)
 
-- Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- An old product is not an unpatchable one: the test that separates the two is vendor support termination, verified by confirming the product no longer receives security fixes from its vendor, not the age of the version or the length of time since its last release.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the vendor is shown to have issued a security fix, or an extended-support contract covering the exact version, within the period the finding calls unpatchable, since either fact restores a remediation path and demotes the item to ordinary version disclosure.
+  - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
+- Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The recognition signal for an unpatchable product is a stated absence " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
-- An old product is not an unpatchable one: the test that separates the two is vendor support termination, verified by confirming the product no longer receives security fixes from its vendor, not the age of the version or the length of time since its last release.
-  - **Disproof:** Refuted if the vendor is shown to have issued a security fix, or an extended-support contract covering the exact version, within the period the finding calls unpatchable, since either fact restores a remediation path and demotes the item to ordinary version disclosure.
-  - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/eol_software/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id eol_software`
```

## 2026-10-04 19:46 — 9 diff lines
- items: 9 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- eol_software@current
+++ eol_software@new
@@ -72,6 +72,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/eol_software/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id eol_software`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 22:28 — 49 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- eol_software@current
+++ eol_software@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE — · OWASP —
-> evidence: 9 items, 9 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 A platform or version past end of life that receives no fixes, on an internet-reachable surface. Distinct from version disclosure: the defect is that no future fix is possible.
 
@@ -27,6 +27,9 @@
 
 ## Recon signals (where to look)
 
+- An internet-facing host past its product's end-of-support date keeps completing TLS handshakes on the certificate it already holds for exactly as long as that certificate's Not After date allows, because holding a certificate valid past expiry requires someone to re-issue it and nobody does that once the vendor has stopped supporting the product, so a successful handshake proves reachability and says nothing about whether a patch path exists.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the served leaf certificate's notBefore is later than the product's end-of-support date and re-issuance is attributable to an identified party that is demonstrably still shipping signed updates to the host, since that establishes a live remediation path and shows the certificate dates cannot separate maintained assets from abandoned ones.
+  - Sources: <https://cabforum.org/working-groups/server/baseline-requirements/requirements/> · <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>
 - The authoritative signal for whether a product is unpatchable is the vendor's own support lifecycle statement for that specific model and version, and it is not obtainable from any published government list of unsupported devices.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a published, authoritative list of end-of-service devices with per-model support status becomes available from a government publisher, since that would displace the per-vendor lifecycle lookup as the primary determination path.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
@@ -46,6 +49,12 @@
   - **Disproof:** Refuted if the vendor supplies a compensating control that removes the exploited condition without updating the product, for example disabling the affected service or protocol entirely, which would satisfy the guidance without decommissioning the platform.
   - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
 
+## Tests
+
+- An asset on a release line whose last phase carrying security updates has already ended is unpatchable even while the same product name is still supported, because support end is published per release line and per servicing channel rather than per product, so a non-LTS line or a build past its own end-of-servicing date has no patch path that the product-level date would wrongly suggest still exists.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the vendor's lifecycle documentation shows a single support-end date for the product that applies to every release line and servicing channel regardless of LTS designation or service pack, for example one date and no per-line rows, since that would remove the per-line boundary and make the product-level end date the only unpatchability test.
+  - Sources: <https://learn.microsoft.com/en-us/lifecycle/definitions> · <https://www.oracle.com/java/technologies/java-se-support-roadmap.html>
+
 ## False-positive rules (when to reject it)
 
 - An old product is not an unpatchable one: the test that separates the two is vendor support termination, verified by confirming the product no longer receives security fixes from its vendor, not the age of the version or the length of time since its last release.  _(merged 1 duplicate row(s))_
@@ -54,6 +63,12 @@
 - Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The recognition signal for an unpatchable product is a stated absence " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
+
+## Variants
+
+- An internet-facing application whose third-party component comes from an abandoned upstream project can never receive a fix for a CVE assigned after the abandonment, because no maintainer exists to accept and ship the patch, so the unpatchable condition is inherited from the dependency and survives every patch-management cycle applied to the application itself.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the upstream project has since shipped a release that fixes the specific CVE, or when the deployment consumes a maintained downstream fork maintained by the original developer or a trusted proxy for that developer, since either fact restores an accepting maintainer and a real patch path and demotes the asset to ordinary component patching.
+  - Sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/>
 
 
 ## Hunt procedure
```

## 2026-10-31 06:41 — 40 diff lines
- items: 12 (supported 9), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- eol_software@current
+++ eol_software@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE — · OWASP —
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 12 items, 9 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 A platform or version past end of life that receives no fixes, on an internet-reachable surface. Distinct from version disclosure: the defect is that no future fix is possible.
 
@@ -33,7 +33,7 @@
 - The authoritative signal for whether a product is unpatchable is the vendor's own support lifecycle statement for that specific model and version, and it is not obtainable from any published government list of unsupported devices.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a published, authoritative list of end-of-service devices with per-model support status becomes available from a government publisher, since that would displace the per-vendor lifecycle lookup as the primary determination path.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
-- The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or a long gap since release.  _(merged 1 duplicate row(s))_
+- The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or a long gap since release.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted if the disconnect or no-update instruction is shown to have been issued for a reason other than lifecycle state, for example a temporary withdrawal pending a legal or safety hold that the vendor later reversed with a supported build.
   - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print> · <https://endoflife.ai/article-eol-calendar-alerts>
 
@@ -42,7 +42,7 @@
 - Use of unsupported or end-of-life software is filed as a dangerous practice rather than a routine hygiene gap, and the observed exploitation of such devices is by state-linked actors who target them precisely because no vendor updates arrive.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the named device class is shown to still receive vendor firmware or security patches under a paid or contractual support arrangement, or if a government attestation attributes exploitation of that exact device class to a commodity crimeware operator with no state linkage, which would weaken the severity without refuting the practice classification.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
-- When a known-exploited vulnerability lands on a product that is already past its end-of-life date, the required action is disconnect or replacement, because the vendor will never ship a fix and the entry has no patch path at all.  _(merged 1 duplicate row(s))_
+- When a known-exploited vulnerability lands on a product that is already past its end-of-life date, the required action is disconnect or replacement, because the vendor will never ship a fix and the entry has no patch path at all.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the vendor's own security advisory for the same CVE publishes a fixed build that is still downloadable and supported, or when CISA later replaces the disconnect action on that KEV row with an 'apply update' action, which would show a patch path existed after all.
   - Sources: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print> · <https://endoflife.ai/article-eol-calendar-alerts>
 - Where mitigations are unavailable, the mandated action for an unpatchable product is to discontinue or decommission it on a fixed deadline, so an unpatchable exposure is closed by removal from the network rather than by any future patch.  _(merged 1 duplicate row(s))_
@@ -60,7 +60,7 @@
 - An old product is not an unpatchable one: the test that separates the two is vendor support termination, verified by confirming the product no longer receives security fixes from its vendor, not the age of the version or the length of time since its last release.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the vendor is shown to have issued a security fix, or an extended-support contract covering the exact version, within the period the finding calls unpatchable, since either fact restores a remediation path and demotes the item to ordinary version disclosure.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
-- Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a eol_software finding until it is distinguished from the adjacent behaviour this class also covers. "Internet reachability is the amplifier that separates a reportable unpatchable-platform finding from an inventory note, because a perimeter-positioned unpatched device converts one known or novel flaw into initial access and lateral..." and "The recognition signal for an unpatchable product is a stated absence of update availability in the advisory or catalog entry itself, such as an entry that tells the defender to disconnect the product, rather than an old version number or..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The recognition signal for an unpatchable product is a stated absence " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://endoflife.ai/article-eol-calendar-alerts> · <https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 12 (supported 9), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- eol_software@current
+++ eol_software@new
@@ -86,7 +86,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/web/eol_software/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id eol_software`
+Full class document: `skills/web/eol_software/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id eol_software`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 12 (supported 9), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- eol_software@current
+++ eol_software@new
@@ -5,7 +5,8 @@
 
 # End-of-life and unpatchable platform — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
