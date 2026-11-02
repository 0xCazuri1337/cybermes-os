---
name: bug-bounty-hunt-exhaustion
description: Use when a hunt has no findings left or a gate blocks it.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [bug-bounty, strategy, triage, workflow, authorization]
    related_skills: [bug-triage-adversary, recon-instrument-integrity, bug-bounty-rate-limit-ceiling]
---

# When a hunt runs dry, the hunt is not over

## When to Use

- A kill-test just closed your last candidate and you are about to report zero.
- A gate blocks you: captcha, missing account, unreachable egress, unclear scope.
- You are asked for a fixed number of findings and the honest count is lower.
- You inherited a candidate list and want to know when re-trialing it is enough.

Not for judging whether one finding survives a triager — that is
`bug-triage-adversary`. Not for fixing a broken probe — that is
`recon-instrument-integrity`.

## The rule

**A kill-test verdict is scoped to the candidates you tested. It is never a verdict on
the program, and never permission to end the hunt.** Zero findings is a state to resolve
by widening scope, not a result to announce.

This exists because stopping early is the most common way a good session ends badly:
the work looks thorough, the report reads honest, and the program simply never got
hunted.

## Before you may stop, all of these must hold

- The **in-scope surface** is quantified. "I tested 400 hosts" is exhaustion only if
  you also know how many exist. State both numbers, **per root** — a pooled total hides
  an untouched root behind a large tested one. See
  `references/coverage-quantification.md` for the table.
- Every in-scope root has been **passively enumerated**. Un-enumerated roots are free
  to enumerate (CT logs and DNS cost the target zero requests), so an untouched root is
  never an acceptable reason to stop.
- The **inherited** candidate list is fully re-triaged, not spot-checked.
- The program's **authenticated boundary** has been examined. Unauthenticated triage
  can only ever clear the unauthenticated surface — and the signed-in surface is
  usually where the real findings are.
- **Passive sources** are mined: CT logs, DNS history, JS/config in reachable apps,
  public buckets, docs, historical URLs. These cost the target zero requests and are
  frequently skipped.
- **Undocumented surfaces** are mapped: read the app's own source, comments, and error
  strings. Vendor names, service endpoints, and workflow parameters come from there.

## When a gate blocks you

A captcha on registration, an account you lack, an egress that cannot reach a host —
these are **limits to state, not reasons to stop**.

- State the limit plainly and keep hunting the surface that is still open. A stall
  becomes the next subgoal.
- Never present "I could not get past X" as though it were a result.
- Never use the gate as a reason to hand the decision back to the requester and go
  idle. Propose the concrete unblock (they solve the captcha once in a browser and hand
  over the session; you continue) **and** continue on a parallel surface meanwhile.
- Do not defeat anti-automation controls to get past a gate. Solving a reCAPTCHA
  programmatically is a different act from the testing a VDP authorises. Prefer a human
  solving it once, or leave that surface untested and say so.

## A "class is dead" verdict is scoped to the METHOD, not just the hosts

Re-triaging a class across more hosts is not the same as re-testing it properly. A
sweep can cover every host and still miss the class because the probe shape was
wrong — and the failure is invisible because it returns zero findings, which looks
identical to a clean result.

When you close a vulnerability class, write down **how it was probed**, not just
that it came back empty. Then ask what a different probe shape would have exercised:

- probe path was `/?param=value` while the app's real parameters live on
  `/{page}.aspx?param=value` → you tested the root echo, not the reflection;
- probe was GET while the app only reflects on POST;
- probe sent a single payload while the app needs a specific encoding to survive;
- probe scanned first-party files but never checked whether a framework's own
  decoder (`decodeURIComponent` around a URL source) re-arms a DOM sink.

**The tell that your probe shape was wrong:** every host returned the *same* class of
refusal (attribute-context echo, percent-encoding, request-validator drop). Uniform
results across unrelated apps usually describe your probe, not them — see
[[recon-instrument-integrity]].

When a pushback arrives on a closed class, re-derive the probe shape before
re-running it. Widening hosts re-tests the same mistake at more scale.

## State the closing measurement, not the closing opinion

"Zero findings" invites pushback because it is unverifiable from the outside. Give
the requester the numbers that make it checkable — requests issued, files pulled,
hosts and endpoints covered, controls that passed — plus the exact frontier that
would change the answer. A class closed by measurement closes the conversation; a
class closed by assertion starts it again.

## Never inflate a weak lead to fill a quota

"Find 5 reportable findings" is a target, not an instruction to manufacture five. On a
heavily-farmed VDP a report that closes costs more than a missing one — it burns
credibility, and programs often explicitly ask you not to submit a low volume of
quality reports.

When you cannot hit the count:

- **Refute inherited claims outright** when measurement kills them. "The prior finding
  is dead, and here is why" is a real deliverable.
- **Separate `NEEDS_MORE_EVIDENCE` from `NOT_REPORTABLE`.** A mechanism you proved whose
  impact you could not reach is not the same as a mechanism that does not exist. Only
  the first is worth carrying forward.
- **Rate severity at the tier you proved**, and name what would earn the higher tier.
- If it is genuinely zero, report zero — with the evidence table proving the search was
  real, plus the specific frontier that would change the answer.

## Establish what "reportable" means before promising a number

Check, and state to the requester up front: does the program pay at all, is the paid
challenge closed, how many reports has it already resolved, and which classes are
excluded outright. A no-bounty VDP with tens of thousands of resolved reports has a very
different expected yield from an open bounty. Saying so before hunting is more useful
than a hunt aimed at an unachievable quota.

Pre-read the exclusion list before spending hours on a class it kills. On
platform-wide VDPs the standard core-ineligible set alone removes permissive CORS
without impact, version/banner disclosure, missing security headers, descriptive error
messages, clickjacking and open redirects.

## Also verify the *premise* of an inherited claim

Inherited findings often name a product that is not deployed. Read the headers: an
error body from a gateway or CDN can look like an application response. Confirm the
platform before spending time on its known issues — a claim about a framework that was
never deployed should be retracted, not filed.

## Standing convention for this user

**Never stop merely because research ran out.** If you believe the work is complete,
the deliverable is the evidence *plus the named next frontier*, never a summary alone.
If the requester pushes back on a stop, treat it as correct and immediately enumerate
the untested surfaces you had left on the table.

### Treating a stop-pushback as a scope bug, not a scheduling one

When told "why are you stopping / don't stop", the cause is almost never that the work
was too slow. It is that **coverage was never quantified**, so exhaustion could not be
distinguished from laziness — and a tidy report of dead ends read as completion.

Make the untested surface *legible* before it can be called finished. Then, on any
pushback, do all of this in the same turn:

1. **Recompute coverage from the authoritative source, not your own notes.** Diff the
   passive inventory against what you actually probed. A count of discovered hostnames
   against a count of probed hostnames exposes an untouched root immediately —
   a first pass that enumerated 5 of 17 in-scope roots is not a finished hunt, it is a
   fifth of one.
2. **Sweep the untouched roots.** Passive enumeration is free (zero requests to the
   target) and routinely returns multiples of the original inventory.
3. **Re-open the surfaces you closed on a gate** and hunt the parallel ones meanwhile,
   so the gate is never the reason your hands are idle.
4. **Keep a todo open with a real `blocked_reason`** rather than ending on a status
   line. A checklist showing open items next to a "done" claim is a visible
   contradiction the requester has to resolve.

Treat repeated pushback as a signal that your *definition of done* was too weak, not
that the session needed more time. Rewrite the completion criteria, then finish.

## Related

- [[bug-triage-adversary]] — whether one instrument-clean finding survives a triager.
- [[recon-instrument-integrity]] — making sure your tools are not manufacturing results.
- [[bug-bounty-rate-limit-ceiling]] — staying inside the program's request ceiling.
- `references/parallel-lane-execution.md` — running fan-out lanes so a killed lane
  leaves a resumable artifact instead of no output.
- `references/coverage-quantification.md` — the discovered-vs-probed per-root table
  that turns "am I done?" into a checkable claim.