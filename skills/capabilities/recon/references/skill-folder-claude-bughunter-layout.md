# skill-folder-claude-bughunter-layout

Source: `attack-surface/skill-folder-claude-bughunter-layout/SKILL.md` (preserved verbatim during consolidation).

---

---
name: skill-folder-claude-bughunter-layout
description: How to organize a bug-hunting / pentest skill folder to match the elementalsouls/Claude-BugHunter repo layout (skills/<name>/SKILL.md, hunt-* naming, sources/report_count frontmatter). Use when the user asks to "make the skill folder look like Claude-BugHunter" or to restructure security skills.
sources: authorized-engagement
report_count: 1
---

# Skill folder layout — Claude-BugHunter style

## When to use
User wants a security/bug-bounty skill bundle restructured to match `elementalsouls/Claude-BugHunter` (83 skills, MIT/CC-BY-4.0).

## Target layout (faithful mirror)
```
<folder>/
  README.md  INSTALL.md  USAGE.md  ENGAGEMENTS.md  CONTRIBUTING.md  SECURITY.md  CHANGELOG.md
  skills/
    hunt-<class>/SKILL.md        # vuln classes: idor, ssrf, sqli, xss, jwt-crypto, oauth, open-redirect, cors, csrf, graphql, lfi, xxe, ssti, race-condition, business-logic, spa-api, ...
    recon-scope-triage/SKILL.md
    web2-recon/SKILL.md
    offensive-osint/SKILL.md  (+ README.md, references/*.md, scripts/*)
    osint-methodology/SKILL.md
    redteam-mindset/SKILL.md
    bug-bounty/SKILL.md  bb-methodology/SKILL.md  bb-local-toolkit/SKILL.md
    triage-validation/SKILL.md  evidence-hygiene/SKILL.md  report-writing/SKILL.md  redteam-report-template/SKILL.md  security-arsenal/SKILL.md
    # + platform/tech-specific: hunt-aspnet, hunt-laravel, hunt-nextjs, hunt-springboot, hunt-nodejs, hunt-grpc
    # + enterprise identity/infra matrices: m365-entra-attack, okta-attack, cloud-iam-deep, enterprise-vpn-attack, vmware-vcenter-attack, supply-chain-attack-recon
```

## SKILL.md frontmatter (exact convention)
```yaml
---
name: hunt-<class>            # kebab; hunt- prefix for vuln classes
description: <one line: what it hunts + when to use + what pays>
sources: hackerone_public | github | authorized-engagement | portswigger_research
report_count: <N>            # # of real disclosed reports the skill is grounded in
---
```

## SKILL.md body pattern
1. `# HUNT-<CLASS>` title
2. `## Crown Jewel Targets` — why it pays / highest-value asset types
3. `## Attack Surface Signals` — URL params, headers, JS patterns, tech-stack signals
4. `## Step-by-Step Hunting Methodology` — phased, with real `bash`/`curl`/payload snippets
5. `## Bypass Table` / `## Chain Table` / `## Validation` (where relevant)
6. `## Related Skills & Chains`

## How to rebuild (mirror from source)
```bash
# Get blob list
curl -s "https://api.github.com/repos/elementalsouls/Claude-BugHunter/git/trees/main?recursive=1" > tree.json
# Download every path under skills/ into <folder>/
python3 - <<'PY'
import json,os,subprocess
d=json.load(open('tree.json')); base="https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/"
for t in d['tree']:
    if t['type']=='blob' and t['path'].startswith('skills/'):
        dest=os.path.join('<folder>',t['path']); os.makedirs(os.path.dirname(dest),exist_ok=True)
        subprocess.run(["curl","-s","--max-time","30","-o",dest,base+t['path']])
PY
```
Then remove any OLD flat top-level skill dirs so only `skills/` + top-level `.md` remain (exact clone look). CAUTION: the `keep` list in a purge loop must literally contain `skills` (no leading space) or it gets deleted — re-mirror if that happens.

## Pitfalls
- Don't leave old flat `<class>/SKILL.md` dirs at top level — they clash with the `skills/` layout.
- The heavy harness dirs (cbh/, commands/, engine/, docs/) are tooling, not "the skill folder" — mirror only if asked.
- Preserve rich skills' `references/` + `scripts/` (e.g. offensive-osint).

