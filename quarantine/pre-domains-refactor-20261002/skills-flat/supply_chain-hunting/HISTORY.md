# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 3 (supported 3), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 3 (supported 3), FP rules 0, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 1104 · OWASP A06:2021
 > evidence: 3 items, 3 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
 
```

## 2026-10-02 11:03 — 47 diff lines
- items: 6 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1104 · OWASP A06:2021
-> evidence: 3 items, 3 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 6 items, 6 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 Trust placed in a component, its registry or its build exceeds what was actually verified.
 
@@ -33,5 +33,33 @@
   - **Disproof:** If the token is scoped to a single immutable version, already revoked, or otherwise unable to publish, no further version can be shipped and propagation does not occur.
   - Sources: <https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/> · <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
 
+## Validation bar (how to prove it)
+
+- A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.
+  - **Disproof:** Refuted when the integrity hash of the resolved artifact matches the registry-published hash for that exact version and no unauthorized publish, yank, or token-scope event exists on the package account; absent either the byte mismatch or the publish-event evidence, the CVE in the scan report is a patchability finding.
+  - Sources: <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
+
+## False-positive rules (when to reject it)
+
+- A CVE recorded against a third-party library in your dependency tree is evidence of an unmaintained or vulnerable component, not of supply-chain compromise, because compromise requires the attacker to have published or substituted the artifact your build actually consumed.
+  - **Disproof:** Refuted as a compromise claim when the version your build resolved matches the legitimate published release of the package, no unauthorized publish or account-takeover event exists on the registry, and the finding reduces to the CVE identifier in a scan report; refuted as unmaintained-component exposure only when the CVE's fixed version is already present in your lockfile.
+  - Sources: <https://cwe.mitre.org/data/definitions/1104.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
+
+## Chaining opportunities
+
+- A CI runner or publish credential that leaves its intended environment supplies both the propagation primitive and the delivery stage, so a poisoned artifact reaches hosts by installing itself as an agent rather than by exploiting them.
+  - **Disproof:** Refuted if the CI runner's egress is restricted to the registry and no publish token exists on the runner, or if the delivered component is a passive data artifact with no execution hook on install; a compromised credential with no propagation path and no agent behaviour stops at build compromise without host execution.
+  - Sources: <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026>
+
+## Rejected before you report
+
+- **A CVE recorded against a third-party library in the dependency tree means the build was compromised by a supply-chain attack.**
+  - Killed by: The resolved artifact matched the registry-published hash and no unauthorized publish, yank, or token-scope event existed on the account; the CVE described a defect in the legitimate release, which is a patch, not a compromise.
+  - Rule: A CVE in a dependency scan is a patchability finding, not a supply-chain compromise. Compromise requires either a byte-level mismatch between the resolved artifact and the registry-published one, or an unauthorized publish event on the package account. Check both before filing.
+
+## Chains to
+
+- `exposed_rmm` (3 shared chain(s))
+
 ---
 Full class document: `classes/supply_chain.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 6 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- supply_chain@current
+++ supply_chain@new
@@ -62,4 +62,4 @@
 - `exposed_rmm` (3 shared chain(s))
 
 ---
-Full class document: `classes/supply_chain.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
+Full class document: `skills/Web/supply_chain/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id supply_chain`
```
