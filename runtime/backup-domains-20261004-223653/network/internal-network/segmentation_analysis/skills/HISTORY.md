# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 20 (supported 20), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 20 (supported 20), FP rules 2, chains 1, state mature

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -88,4 +88,4 @@
   - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ---
-Full class document: `domains/network/internal-network/segmentation_analysis/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
+Full class document: `domains/network/internal-network/segmentation_analysis/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
```

## 2026-10-02 19:37 — 67 diff lines
- items: 7 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-1188 · OWASP —
-> evidence: 20 items, 20 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 7 items, 5 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.
 
@@ -26,51 +26,12 @@
 
 ## Techniques (what to change)
 
-- While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them to cyberattacks .
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While accessing and managing systems such as programmable logic controllers (PLCs) and hum".
-  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges.
+- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".
   - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them to cyberattacks .
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While accessing and managing systems such as programmable logic controllers (PLCs) and hum".
-  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges.
+- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".
   - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- We will cover how to identify, exploit, and prevent each of them through various methods.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- If improperly configured or implemented, common web security vulnerabilities such as Information Disclosure, SQL Injection, and Insecure Direct Object Reference (IDOR) may arise.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If improperly configured or implemented, common web security vulnerabilities such as Infor".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Binary exploitation is a core tenet of penetration testing, but learning it can be daunting.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Binary exploitation is a core tenet of penetration testing, but learning it can be dauntin".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be running some version of Windows or Linux.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be ru".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
 - In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.
   - **Disproof:** Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.
   - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
```

## 2026-10-03 01:46 — 49 diff lines
- items: 8 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-1188 · OWASP —
-> evidence: 7 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 8 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.
@@ -28,25 +28,31 @@
 
 - As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".
-  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
+  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
 - As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".
-  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
+  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
 - In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.
   - **Disproof:** Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.
   - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.
+- Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents. _(unverified)_
   - **Disproof:** If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.
-  - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1918.html>
 
 ## False-positive rules (when to reject it)
 
 - Reject a segmentation_analysis finding until it is distinguished from the adjacent behaviour this class also covers. "While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them..." and "Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Remote-session segmentation analysis has no single universal indicator" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://academy.hackthebox.com/catalogue/paths>
+  - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.
   - **Disproof:** Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
+
+## Evidence requirements
+
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (segmentation_analysis.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ---
 Full class document: `domains/network/internal-network/segmentation_analysis/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
```

## 2026-10-04 00:43 — 66 diff lines
- items: 8 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -20,39 +20,51 @@
 
 ## Recon signals (where to look)
 
-- Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.
+- Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.
   - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
-- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. _(unverified)_
+- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".
   - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
-- As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".
-  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
-- In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.
+- In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.  _(merged 1 duplicate row(s))_
   - **Disproof:** Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.
   - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents. _(unverified)_
+- Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1918.html>
 
 ## False-positive rules (when to reject it)
 
-- Reject a segmentation_analysis finding until it is distinguished from the adjacent behaviour this class also covers. "While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them..." and "Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
+- Reject a segmentation_analysis finding until it is distinguished from the adjacent behaviour this class also covers. "While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them..." and "Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Remote-session segmentation analysis has no single universal indicator" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.
-  - **Disproof:** Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (segmentation_analysis.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
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
 Full class document: `domains/network/internal-network/segmentation_analysis/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
```
