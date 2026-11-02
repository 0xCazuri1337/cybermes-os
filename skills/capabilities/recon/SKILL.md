---
name: recon
description: "Canonical recon capability consolidating 29 sub-skills across attack-surface, OSINT, scope-triage, secrets, and subdomain discovery. Use when hunting or validating reconnaissance, asset discovery, OSINT, subdomain enumeration, source/secret leaks, and attack-surface mapping."
sources: consolidated
---

# RECON — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for reconnaissance and attack-surface mapping across external, cloud, identity, and web application targets. It consolidates 29 previously separate sub-skills spanning attack-surface tooling, OSINT, scope triage, secret/NTLM disclosure, and subdomain discovery into one operational entry point. Original sub-skills are preserved under their directories and mirrored in `references/` for provenance and rollback.

Primary objectives:
- Discover and inventory an organization's external attack surface: domains, subdomains, IPs, cloud assets, apps, APIs, people, and exposed services.
- Validate ownership/scope before testing; separate real assets from namespace-collision noise.
- Identify secret, source-code, and NTLM information leaks and credential exposures.
- Produce reproducible, impact-rated recon findings with remediation guidance.
- Chain into vulnerability hunting only after scope is confirmed and evidence is captured.

## 2. Scope

In scope:
- Subdomain enumeration and DNS/zone reconnaissance (passive + active).
- OSINT: people, org, identity fabric (Entra/Okta/ADFS/Google/M365), breach/corp correlation, threat-actor infra.
- Attack-surface tooling: nmap, shodan, SPA auth-gate bypass, bot-mitigated recon, egress/captcha handling, dispatch.
- Scope/ownership triage of ASM/recon output (repos, buckets, mobile apps, breach corpora).
- Secret and source-leak discovery: JS/source maps, paste sites, NTLM/Negotiate info disclosure.
- Typosquatting/domain permutation analysis and brand monitoring.
- PfSense firewall configuration review where in scope.

Out of scope (hand off):
- Vulnerability exploitation on discovered assets -> appropriate capability (sqli, ssrf, xss, etc.).
- Cloud misconfiguration deep-dive -> `hunt-cloud-misconfig` / cloud capabilities.
- Credential stuffing/ATO -> `hunt-ato` / identity capabilities.
- Network penetration beyond authorized scope -> offensive-testing capabilities.

## 3. Invocation and routing

Use this capability when:
- You need to map an organization's external footprint before vulnerability testing.
- You need OSINT on a person, entity, or threat actor.
- You need to enumerate subdomains, DNS, or cloud assets.
- You need to triage ASM/recon output for ownership.
- You need to find leaked secrets, source code, or NTLM info.
- You need to bypass SPA auth gates or bot walls during authorized recon.

Routing notes by group:
- Attack surface: `references/hunt-dispatch.md`, `references/bb-local-toolkit.md`, `references/bot-mitigated-spa-recon.md`, `references/spa-auth-recon.md`, `references/scanning-network-with-nmap-advanced.md`, `references/performing-ip-reputation-analysis-with-shodan.md`, `references/bugbounty-ops-egress-captcha.md`, `references/redteam-mindset.md`, `references/skill-folder-claude-bughunter-layout.md`, `references/find-skills.md`, `references/configuring-pfsense-firewall-rules.md`.
- OSINT: `references/osint-methodology.md`, `references/offensive-osint.md`, `references/collecting-open-source-intelligence.md`, `references/conducting-external-reconnaissance-with-osint.md`, `references/building-threat-actor-profile-from-osint.md`, `references/tracking-threat-actor-infrastructure.md`, `references/performing-open-source-intelligence-gathering.md`, `references/performing-osint-with-spiderfoot.md`, `references/performing-brand-monitoring-for-impersonation.md`, `references/performing-ai-driven-osint-correlation.md`.
- Scope triage: `references/recon-scope-triage.md`.
- Secrets: `references/hunt-ntlm-info.md`, `references/hunt-source-leak.md`, `references/performing-paste-site-monitoring-for-credentials.md`.
- Subdomains: `references/hunt-subdomain.md`, `references/performing-dns-enumeration-and-zone-transfer.md`, `references/performing-subdomain-enumeration-with-subfinder.md`, `references/analyzing-typosquatting-domains-with-dnstwist.md`.

## 4. Inputs and outputs

Inputs:
- Target organization name, domains, in-scope hostnames/IP ranges, authorization letter.
- Seed data: brand names, emails, employee names, GitHub orgs, cloud tenants.
- Authentication material for SPA/auth-gate recon (authorized test accounts).
- Prior ASM/recon exports, breach corpora, repo/bucket/app lists.

Outputs:
- Attack-surface inventory (domains, subdomains, IPs, services, tech stack, owners).
- OSINT dossier (people, identities, infra, breach correlation, threat-actor mapping).
- Scope-triage verdicts (owned vs collision noise) with ownership signals.
- Secret/source-leak findings with proof and remediation.
- Subdomain/DNS findings (dangling records, takeovers, zone transfers).
- Evidence bundle (requests/responses, tool output, screenshots).

## 5. Preconditions and authorization

- Confirm written authorization and defined scope before any active probing.
- Respect rate limits, robots, and third-party ToS; do not probe out-of-scope or unrelated same-named assets.
- Ownership is guilty-until-proven: an asset is in scope only when a concrete ownership signal ties it to the target.
- Use only authorized test accounts; do not access other users' data.
- Passive OSINT first; active scanning only within approved windows and hosts.
- Stop at tenant/org boundaries; document out-of-scope assets rather than test them.

## 6. Reconnaissance

Recon steps:
1. Seed discovery: identify primary domains, brand terms, org identifiers, cloud tenants, and known assets.
2. Asset expansion: subdomain enumeration (passive + active), DNS/zone transfers, reverse DNS, certificate transparency, search engines, code repos.
3. Service fingerprinting: port scan, banner grab, tech-stack detection, WAF/CDN identification.
4. Cloud/identity surface: buckets, SaaS, SSO/IdP fingerprinting, M365/Google Workspace enumeration (authorized).
5. OSINT enrichment: people, emails, social, breach correlation, threat-actor infra, crypto tracing where authorized.
6. SPA/API surface: defeat auth gates and bot walls to reach authenticated API endpoints.
7. Scope triage: verify ownership of every discovered asset before testing.
8. Secret/source-leak sweep: JS bundles, source maps, paste sites, NTLM info disclosure, git history.
9. Brand/typosquat monitoring: permutation analysis and impersonation detection.

See references by group in section 3.

## 7. Detection methodology

Core detection flow:
1. Collect seeds and run passive expansion (subdomains, DNS, CT logs, search dorks).
2. Validate liveness and fingerprint services; record tech stack and hosting.
3. Enumerate subdomains actively (wordlists, brute force, permutations) within rate limits.
4. Test for zone transfer and DNS misconfigurations.
5. Run OSINT pipeline: identity fabric, breach correlation, infra mapping.
6. Bypass SPA auth gates / bot walls to reach authenticated APIs.
7. Triage ownership for every asset (repos, buckets, apps, breach entries).
8. Sweep for secrets/source leaks (JS, source maps, paste sites, NTLM).
9. Analyze typosquats and brand impersonation.
10. Document findings with evidence; mark unconfirmed items as leads, not findings.

## 8. Technique selection

Select techniques by observed behavior:
- Large org with many assets -> scale tactics, automation, parallel enumeration.
- Common/dictionary brand name -> aggressive scope triage first (collision noise).
- SPA with auth-gated API -> SPA auth recon / bot-mitigated recon.
- Bot wall / CAPTCHA -> egress/captcha handling, browser fallback.
- Cloud-heavy target -> bucket enumeration, tenant fingerprinting, SaaS discovery.
- Leak-prone target -> JS/source-map sweep, paste monitoring, NTLM info.
- Threat-actor investigation -> infrastructure tracking, OSINT correlation.
- Need dispatch of skill sets -> hunt-dispatch.

## 9. Execution steps

1. Confirm authorization and scope; record in-scope hosts/ranges.
2. Run passive seed expansion and subdomain enumeration; deduplicate.
3. Fingerprint live hosts and services; capture tech stack.
4. Perform active enumeration within rate limits.
5. Execute OSINT enrichment and identity-fabric mapping.
6. Bypass auth gates/bot walls as needed for SPA/API recon.
7. Triage ownership for all discovered assets; discard collision noise.
8. Sweep for secrets, source leaks, NTLM info.
9. Monitor typosquats/brand impersonation.
10. Compile inventory and evidence; hand off confirmed assets to vuln capabilities.

## 10. Tool usage

- DNS/subdomains: subfinder, amass, dnsx, massdns, dig, fierce, knockpy.
- Port/service: nmap, masscan, shodan, censys, httpx.
- Web/SPA: Playwright, browser automation, curl, ffuf, gau, waybackurls.
- OSINT: SpiderFoot, theHarvester, Maltego, Shodan, Censys, GitHub search, breach databases (authorized).
- Secret scanning: trufflehog, gitleaks, custom regex, paste monitors.
- Cloud: cloud_enum, s3scanner, bucket-finder.
- Automation: Python, bash, jq, parallel.

See references for tool-specific usage and API details.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Subdomain enum: `subfinder -d example.com -all -silent | sort -u`.
- DNS zone transfer: `dig axfr @ns1.example.com example.com`.
- NTLM info: probe SMB/HTTP/Exchange for NTLM challenge and decode domain/workstation.
- Source leak: fetch `*.js.map`, `.git/`, backup files, debug endpoints.
- Paste monitoring: search paste sites for target domain/email patterns.
- Typosquat: generate permutations with dnstwist and check resolution.
- SPA auth: replay authenticated API requests with full header control.
- Ownership: verify repo owner, bucket content, app publisher, breach entry.

## 12. Evidence

Each finding must include:
- Exact command/tool output and raw requests/responses where applicable.
- Asset identifier (domain, IP, URL, repo, bucket) and ownership signal.
- Timestamp, tool version, and scope confirmation.
- For leaks: proof of exposed secret/data (redacted in report) and blast radius.
- For takeovers: DNS record, dangling target, and control proof.
- For OSINT: source citations and confidence level.

## 13. Reproduction and validation

- Reproduce enumeration and discovery steps in a clean environment.
- Validate ownership signals independently (not just scanner keyword match).
- Confirm dangling records/takeovers with controlled verification.
- Confirm leaks are real and not test/placeholder data.
- Mark as refuted/lead if ownership or exploitability cannot be confirmed.

## 14. False-positive rejection

Reject or downgrade when:
- Asset is not provably owned by the target (namespace collision).
- Subdomain is a wildcard/catch-all without real service.
- Leak is test data, example, or revoked credential.
- NTLM info is generic/default and not target-specific.
- Typosquat domain is unregistered or parked without malicious content.
- OSINT correlation is low-confidence or single-source.

## 15. Impact

Impact guidance:
- Critical: confirmed subdomain takeover on high-value domain; exposed production secrets/PII; full tenant/org compromise via leaked creds.
- High: verified ownership of cloud assets with sensitive data; authenticated API surface exposed; identity-fabric enumeration enabling ATO.
- Medium: information disclosure aiding further attacks; dangling DNS; moderate OSINT exposure.
- Low: informational findings, unconfirmed leads, hardening gaps.

Always tie impact to business risk, affected scope, and exploitability; avoid severity inflation from presence alone.

## 16. Reporting

Report template:
- Summary: asset/finding type, mechanism, impact.
- Scope/authorization: test window, in-scope confirmation.
- Steps to reproduce: numbered, minimal, including commands and outputs.
- Proof of concept: raw evidence (redacted secrets).
- Impact: business and data scope, affected users, exposure.
- Remediation: remove leaks, fix DNS, enforce ownership verification, tighten scope/monitoring, harden SPA/API.
- References: relevant standards (OWASP, CWE) and source citations.

## 17. Failure modes

- No assets found -> expand seeds, try alternate sources, passive-only mode.
- Too much noise -> apply scope triage, ownership signals, dedup.
- Bot wall/CAPTCHA -> use browser fallback, egress handling, authorized test windows.
- Rate limiting -> throttle, coordinate, use allowed windows.
- Zone transfer denied -> use passive DNS, CT logs, brute force.
- SPA auth gate -> use spa-auth-recon decision ladder.
- Inconclusive ownership -> mark as lead, do not test.

## 18. References

All 29 sub-skill references are preserved and must resolve:

Attack surface:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/bb-local-toolkit.md` | `bb-local-toolkit` | Local recon tooling |
| `references/bot-mitigated-spa-recon.md` | `bot-mitigated-spa-recon` | Bot-walled SPA recon |
| `references/bugbounty-ops-egress-captcha.md` | `bugbounty-ops-egress-captcha` | CAPTCHA/egress handling |
| `references/configuring-pfsense-firewall-rules.md` | `configuring-pfsense-firewall-rules` | PfSense review |
| `references/find-skills.md` | `find-skills` | Skill discovery |
| `references/hunt-dispatch.md` | `hunt-dispatch` | Skill-set dispatch |
| `references/performing-ip-reputation-analysis-with-shodan.md` | `performing-ip-reputation-analysis-with-shodan` | Shodan IP reputation |
| `references/redteam-mindset.md` | `redteam-mindset` | Operator mindset |
| `references/scanning-network-with-nmap-advanced.md` | `scanning-network-with-nmap-advanced` | Nmap scanning |
| `references/skill-folder-claude-bughunter-layout.md` | `skill-folder-claude-bughunter-layout` | Skill folder layout |
| `references/spa-auth-recon.md` | `spa-auth-recon` | SPA auth-gate bypass |

OSINT:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/building-threat-actor-profile-from-osint.md` | `building-threat-actor-profile-from-osint` | Threat-actor profiling |
| `references/collecting-open-source-intelligence.md` | `collecting-open-source-intelligence` | OSINT collection |
| `references/conducting-external-reconnaissance-with-osint.md` | `conducting-external-reconnaissance-with-osint` | External recon |
| `references/offensive-osint.md` | `offensive-osint` | Offensive OSINT |
| `references/osint-methodology.md` | `osint-methodology` | OSINT methodology |
| `references/performing-ai-driven-osint-correlation.md` | `performing-ai-driven-osint-correlation` | AI-driven OSINT |
| `references/performing-brand-monitoring-for-impersonation.md` | `performing-brand-monitoring-for-impersonation` | Brand monitoring |
| `references/performing-open-source-intelligence-gathering.md` | `performing-open-source-intelligence-gathering` | OSINT gathering |
| `references/performing-osint-with-spiderfoot.md` | `performing-osint-with-spiderfoot` | SpiderFoot |
| `references/tracking-threat-actor-infrastructure.md` | `tracking-threat-actor-infrastructure` | Threat-actor infra |

Scope:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/recon-scope-triage.md` | `recon-scope-triage` | Ownership triage |

Secrets:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-ntlm-info.md` | `hunt-ntlm-info` | NTLM info disclosure |
| `references/hunt-source-leak.md` | `hunt-source-leak` | Source-code leak |
| `references/performing-paste-site-monitoring-for-credentials.md` | `performing-paste-site-monitoring-for-credentials` | Paste-site monitoring |

Subdomains:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/analyzing-typosquatting-domains-with-dnstwist.md` | `analyzing-typosquatting-domains-with-dnstwist` | Typosquatting |
| `references/hunt-subdomain.md` | `hunt-subdomain` | Subdomain hunting |
| `references/performing-dns-enumeration-and-zone-transfer.md` | `performing-dns-enumeration-and-zone-transfer` | DNS/zone transfer |
| `references/performing-subdomain-enumeration-with-subfinder.md` | `performing-subdomain-enumeration-with-subfinder` | Subfinder enumeration |

Original sub-skills remain intact under `attack-surface/`, `osint/`, `scope/`, `secrets/`, and `subdomains/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_recon_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs and bug-bounty programs within scope.
- Mastery criteria: independently discover, validate ownership, and report a recon finding (subdomain takeover, secret leak, or OSINT-driven exposure) with full reproduction and impact.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: dns_enum, exposed_rmm, exposed_services, internal_recon, ldap_enum, service_enumeration, service_enumeration_detail, subdomain_takeover
- Domain knowledge: subdomain_takeover
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
