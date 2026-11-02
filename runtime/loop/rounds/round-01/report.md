# Loop round 01
- at: 2026-10-04T16:41:20+00:00
- model: opencode/space-bunny-free
- worker exit: 0
- elapsed_s: 23.1
- intake file: NONE
- status: no_file

## Cause
The brief was passed as a multi-line argv argument and arrived as ONLY ITS
FIRST LINE. The worker replied "Your message arrived as just the title", ran
`ls -la`, and exited 0. A round that produced zero work while reporting success
— the most dangerous failure mode in this loop, because an exit code alone
would have recorded it as a pass.

(An EARLIER attempt at this round died with `FileNotFoundError [WinError 2]`
before OpenCode started at all: npm installs three shims per binary on Windows,
and native Python cannot exec the `#!/bin/sh` one bash resolves. Fixed by
resolving `opencode.cmd` explicitly.)

## Fixes applied
1. `tools/loop_round.py::opencode_exe()` — resolve the `.cmd` shim.
2. `deliver_prompt()` — write the brief to `prompt.txt` and send a ONE-LINE
   instruction naming it. Verified: all 3 lines of a test prompt came back.
3. The driver asserts the expected artifact exists before recording a round.

## What this round proves
Nothing about OpenCode's capability — it never saw the task. Recorded so the
sequence stays auditable rather than silently skipped.
