---
name: finding-pre-submission-validation
description: Pre-submission quality gate for security findings — validates evidence, reproducibility, scope, duplicates, and impact honesty BEFORE reporting, then runs chaining and impact-escalation analysis (primitive-to-sink A-to-B chains, per-class escalation ladders, severity recalibration). Use when a finding is "ready to submit/report", before writing a bug bounty report or recording a pentest vuln, when asking "is this valid / worth submitting / can it be chained / can impact be escalated", or when triaging scanner output for false positives.
domain: cybersecurity
subdomain: reporting
tags:
- validation
- chaining
- impact-escalation
- reporting
- bug-bounty
- severity
- evidence
- triage
version: '1.0'
license: Apache-2.0
---

# Pre-Submission Validation + Chaining / Impact Escalation

## When this fires
- A finding "works" and you're about to submit it (bounty platform) or record it (pentest report).
- A subagent/scanner reported a vuln and nobody has validated it yet.
- You suspect a finding is too weak to survive triage and want to know if chaining can raise it.
- Before `report_gen` / final pentest report — every recorded finding must have passed the gates.

## Iron rule
**Never submit what you wouldn't want a triager to read at 9am with a hangover.**
A submission that fails validation costs more than no submission: dup flags, reputation, and
informative ratings poison the well for your next real finding. Run the gates; if a gate fails,
either close the gap or downgrade to `suspected` — never submit on hope.

## Pipeline position — MANDATORY ORDERING (do not skip or reorder)

This skill is **STAGE A (STRUCTURAL gate)** in the pre-report validation pipeline. It MUST
run BEFORE `triage-validation` (STAGE B, ACCEPTANCE gate). Both stages must clear before a
finding becomes `REPORTABLE`. This ordering is non-negotiable per the hunting workflow
(`~/.hermes/bug-bounty-hunting-workflow.md` §22) and the corpus index
(`~/.hermes/skills/bug-bounty/INDEX.md` → "MANDATORY PRE-REPORT VALIDATION GATE").

```text
VALIDATED (impact demonstrated)
   ├─ STAGE A  this skill  (scope → dup → repro → evidence → root cause → impact-proven → chain/escalation)
   ├─ STAGE B  triage-validation  (7-Question Gate + 4 pre-sub gates + never-submit + pre-severity)
   └─▶ REPORTABLE
```

If this stage fails: close the gap and re-run, OR downgrade to `suspected` / `VALIDATED BUT
NOT REPORTABLE`, OR mark `REJECTED` with a reason. Do NOT proceed to Stage B or drafting a
report on a finding that has not cleared Stage A. Impact-boundary confirmation (which
security boundary is crossed) uses the reusable checks in `~/.hermes/skills/bug-bounty/validation/`.

## The validation gates — run IN ORDER (cheap first, fail fast)

**Gate 0 — Scope & policy.** Target in scope? Method allowed (no automated scanning / no
brute force / no social engineering clauses)? Asset bounty-eligible? Out-of-policy = report
rejected at best, program ban at worst. STOP here if it fails — no chaining rescues it.

**Gate 1 — Duplicate check.** Program's disclosed reports, previously-fixed issues, public
writeups for the same target/class. A blind dup is wasted submission. (For pentest: check
`state_query resolved_vectors` + existing vulns first.)

**Gate 2 — Reproducibility.** Re-run the PoC from a CLEAN state — fresh incognito session, no
cookies/tokens left over from earlier testing, second account if relevant. If it worked once
and not now, you do not have a finding; you have an anecdote. Steps-to-reproduce must be
self-contained (someone else reproduces them without chatting with you).

**Gate 3 — Evidence integrity.** Every claim maps to a captured artifact: full
request/response pairs, screenshots with payload AND result visible, timestamps. No
"as you can see" pointing at something not attached. Redact your own account data; keep the
minimum real-user data needed to prove impact — never dump more PII than the proof requires.

**Gate 4 — Root cause understood.** You can state the broken/missing control in one sentence
("no ownership re-check on the update endpoint", "CSP allows `unsafe-eval` + a JSONP gadget").
Unexplained behavior gets marked N/A or duped by triagers. If you can't explain it, you haven't
finished testing it.

**Gate 5 — Impact PROVEN, not asserted.** The impact statement is demonstrated in your evidence
(you actually read the other tenant's data / actually received the callback / actually got the
IAM creds) or trivially derivable from a captured primitive. "Theoretically possible" impact =
informative severity. Proven primitive + theoretical extension is fine — state it as
"Further impact possible:" AFTER the proven impact, never instead of it.

**Gate 6 — Not on the junk list** (below) — unless you've chained it into real impact.

Fail any gate → close the gap (re-test, better evidence, dig for root cause, test the chain)
or downgrade. In pentest state: keep it `suspected`, not `confirmed`, until it passes.

## The 7-Question Gate (writeup completeness — all seven must have answers)
1. **What** exact asset/endpoint/parameter is vulnerable?
2. **Why** — what control is broken or missing (root cause)?
3. **Who** can do it — minimum privilege/precondition for the attacker?
4. **Action** — what does the attacker DO (verb + resource + scale)?
5. **So what** — business impact (data leak / ATO / fraud / availability / compliance)?
6. **Why not blocked elsewhere** — WAF, CSP, re-auth, ownership re-check, rate limit — which
   layer SHOULD have stopped it and why it didn't?
7. **Chain?** — what primitive did this give me, and does any OTHER finding or platform
   feature accept that primitive?

## Chaining analysis — the core escalation method

Don't think "can bug A be chained with bug B" classically. Think **primitive → sink**:

1. **Inventory the primitive** the finding gives you:
   read-internal-URL · execute-JS-in-victim · write-file-to-path · read-file-server-side ·
   act-as-other-user · redirect-victim · inject-header · internal-network-reach ·
   leaked-credential · bypass-rate-limit.
2. **Grep your other findings + the platform's features** for SINKS that accept that
   primitive: OAuth redirect_uri (accepts redirect) · cloud metadata (accepts internal URL
   fetch) · admin panel (accepts act-as-other-user) · cron/service loader (accepts
   write-file) · password-reset flow (accepts execute-JS / redirect).
3. **Test the chain NOW while you still have access.** A chain you can't demonstrate is
   a "Further impact possible" footnote, not a severity upgrade. Chaining at report time
   with access expired = writing checks you can't cash.

Classic chain pairs (full matrix + per-class escalation ladders:
`references/chaining-recipes.md`):
```
open redirect      → OAuth/SSO redirect_uri flow        → ATO (token/code theft)
SSRF                → 169.254.169.254 / internal admin   → cloud cred theft → account takeover
any XSS             → admin-visible page / reset email   → ATO / tenant takeover
self-XSS            → + CSRF or open redirect            → promoted to stored-XSS impact
IDOR-read           → PUT/DELETE on the same endpoint    → data modification/destruction
LFI                 → log/session file → poison          → RCE
file upload         → path traversal in stored filename → RCE
CRLF injection      → proxy cache key                   → stored XSS
info disclosure     → internal hostnames/IPs             → SSRF target list
SQLi                → INTO OUTFILE / xp_cmdshell         → RCE
subdomain takeover  → wildcard cookie Domain=.tld        → session theft ATO
S3/bucket leak      → JS bundle inside                   → hardcoded API keys
race condition      → redemption/transfer endpoints      → direct financial fraud
```

**Chains in a pentest** = attack paths: run `attack_path_suggest` (cost-based K-shortest
paths through compromised hosts / creds / vulns) instead of guessing. Record confirmed
chains with `add_relationship` (EXPLOITED_VIA) and `update_vuln` with the chained
evidence so `report_gen` tells the story as one finding, not two weak ones.

## Impact escalation ladders (before submitting at severity X, test rung X+1)
- **XSS**: obscure param → login/admin page → stored → admin-visible stored → cookie/session
  theft → tenant takeover.
- **SSRF**: single internal GET → full response read → metadata cred retrieval → authenticated
  cloud API access.
- **IDOR**: read one object → read ALL objects (loop it, count them) → write → delete →
  cross-tenant admin function.
- **SQLi**: error → UNION read → auth bypass → write → file write → RCE.
- **LFI**: /etc/passwd → app source → config with secrets → log poisoning/session theft → RCE.
- **Open redirect**: any-URL → OAuth flow → token/code theft.
- **Upload**: blocked ext → ext bypass → content-type confusion → polyglot → webroot write → RCE.
Full ladders per class: `references/chaining-recipes.md`.

## Impact statement formula (use verbatim)
> **[Attacker pre-state] can [verb] [resource] [optionally: at scale] without [precondition],
> leading to [business impact: data leak / ATO / fraud / availability loss / compliance].**

- BANNED: "could potentially", "may be able to", "theoretically", "it is possible that".
- USE: "An attacker can…". Quantify (N users, dollar value, reg citation). Cite exact
  endpoint, role, and request body.

## Severity calibration — honesty pays
- Rate the PROVEN impact. Mention theoretical upside only as a separate follow-up line.
- CVSS 3.1 for pentest findings; platform norms for bounty (read the program's own matrix —
  they override generic CVSS).
- Inflating severity = triage downgrade + rep damage. Understating slightly = pleasant surprise.
- Chain proven? Rate the CHAIN's impact, not the link's. A reflected XSS that chains to
  tenant takeover is a high/critical, not a medium — but only with the chain demonstrated.

## Always-rejected junk list (do NOT submit alone — chain or drop)
Missing security headers · self-XSS standalone · logout CSRF · version banners w/o
exploitable CVE · missing Secure/HttpOnly on non-session cookies · autocomplete=off ·
missing rate limiting (unless brute-force demonstrated within program rules) · clickjacking
on non-sensitive pages · generic timing-based user enumeration · raw scanner output with no
manual validation · "hardening suggestion" findings · stack traces without sensitive data.
Each can be PROMOTED to a real finding only as part of a demonstrated chain.

## PentestCode integration
1. Pull findings: `state_query vulns` / `state_query host <ip>`.
2. Validate: dispatch the **critic** subagent on the finding (false-positive check, evidence
   check, CVSS) — it exists for exactly this gate. For bounty solo work, self-review with the
   7-Question Gate after stepping away from the finding for a few minutes.
3. Chain: `attack_path_suggest` for multi-host chains; manual primitive→sink scan for
   app-layer chains; record with `add_relationship` + `update_vuln` (status `confirmed`,
   evidence = chained PoC).
4. Only then: `report_gen` / platform submission.
5. A finding that failed a gate and can't be closed: keep as `suspected` in state with a note
   on which gate failed — never report it as confirmed.

## Final one-pass checklist (the last thing before submit)
```
[ ] in scope, in policy        [ ] not a duplicate
[ ] repro'd from clean state   [ ] evidence attached & matches every claim
[ ] root cause stated           [ ] impact PROVEN (or primitive shown + labeled)
[ ] chain check done (primitive→sink)  [ ] escalation rung above tested
[ ] impact formula sentence written    [ ] severity = proven impact
[ ] junk-list check passed      [ ] 7 questions all answered
```
All boxes ticked → submit. Any unticked → back to work, not to the submit button.
