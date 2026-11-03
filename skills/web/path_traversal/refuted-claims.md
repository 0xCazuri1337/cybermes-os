# Refuted and unverified claims — path_traversal

**Purpose.** Claims that were proposed, examined and **NOT accepted**. They are
recorded so a future session does not regenerate them as if they were new, and
so the reasoning that killed them is preserved.

This file is **not** promoted knowledge. Nothing here may be cited as evidence
for a finding. It exists because the failure mode of a knowledge system is not
only forgetting what was true — it is repeatedly rediscovering what was false,
and shipping it.

Sources: multi-model deliberation rounds (`runtime/loop/deliberation/`), where
independent participants argued this class and cross-examined each other.

---

## R1. Windows `\.` "device name" components increment escape depth — REFUTED

**The claim as proposed.**
"Windows `\.` device name components in user-supplied paths bypass
`../`-oriented traversal filters expecting only `..` sequences, so a payload like
`\.\\..\\..\\..\\windows\\system32\\config\\sam` escapes the base directory on
Windows even though the filter only blocks `../`."

**Why it is wrong.**
1. `\.` is a **no-op relative segment**, not a device name. Windows device names
   are `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`. The claim
   invents a category that does not exist.
2. A no-op segment **cannot add escape depth**. Depth is added only by `..`.
3. Strip every `\.` from the payload and `\..\..\..\windows\system32\config\sam`
   resolves identically at the filesystem.
4. Therefore the claim credits the wrong element. What actually defeats a filter
   keyed on `../` is the **backslash separator itself**: a `/`-splitting filter
   never sees a forward-slash dot-segment in the payload at all. That mechanism
   is real and is recorded separately below.

**What survives.** Only the backslash-separator mechanism, which is a different
claim with a different mechanism and must be verified on its own before use.

**Who caught it.** Participant P3 (practitioner lens) in round 03, in
cross-examination. P1 had produced it; no amount of solo generation would have.

---

## R2. Blind traversal is provable from status codes — REFUTED

**The claim as proposed** (self-rated confidence: **high**).
"A blind traversal attempt can be scored from the status line alone when the
server returns 403 for paths resolving outside the document root and 404 for
in-root misses."

**Why it is wrong.** The 403/404 split is a **heuristic, not proof**. Proxies,
error handlers, WAFs and logging layers produce distinct statuses with no file
ever read. It is not universal server behaviour — many servers return 403 for all
restricted paths regardless of escape, others 404 for everything, others use
entirely different codes.

**Accepted replacement (converged across all three lenses).**
A `path_traversal` finding is confirmed only when the returned **content is
verifiably from outside the intended directory**. Distinct status codes, error
text and timing are supporting signals at most.

**Who retracted it.** P3 itself, in turn 2, after P2 and P1 both attacked it — it
named the confound it had glossed over: "logging, proxy rewriting, and error
handlers can produce distinct statuses with no file ever read."

**Standing note.** A self-rated *high* confidence is not evidence. This claim was
fluent, well-formed, plausible, and wrong.

---

## R3. FastCGI null-byte truncation, as stated — MECHANISM INVERTED

**The claim as proposed.** "A PHP FastCGI null-byte injection (e.g.
`../../etc/passwd\0.jpg`) bypasses extension allowlists when the web [server
truncates at the null byte]."

**The defect.** The claim is internally inverted: an **allowlist match on the
full string succeeds** precisely *because* `.jpg` satisfies it, and the
**kernel** is what truncates at `\x00` — not the application truncating first.

**Status.** The underlying null-byte-truncation class is real and
historically significant, so this is **not discarded** — it is parked pending a
correct rewrite. Do not cite the current wording.

---

## Method note

Each of the three claims above passed a fluent, well-structured first draft from
a capable model. None was caught by asking "is this true?" — each was caught by a
peer being asked to **find the error**, and by requiring every claim to state the
condition that would falsify it.

Corresponding positive finding (accepted, needs source verification before use):
encode-then-validate ordering. A check that compares the raw request path against
an allowlist, while the backend canonicalises percent-encoded octets before
resolving the file, is bypassed — normalisation happens after the comparison
rather than before it.