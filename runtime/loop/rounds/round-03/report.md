# Loop round 03
- at: 2026-10-04T17:02:24+00:00
- model: opencode/space-bunny-free
- worker exit: 124
- elapsed_s: 959.9
- intake file: NONE
- status: no_file

## What happened
The worker ran the full 900s budget and was killed. It was alive and working —
`opencode.exe` was observed at **520 MB RSS** during the round — but it never
produced the intake file. From its round-2 behaviour it spent the budget
reading `wks/*.py`, `orch/*.py`, `quality.py`, `pipeline.py`, `verify_quotes.py`
to learn the gate's rules from source. That invitation came from MY brief
("read the gate source to learn the actual rules"), so the prompt caused the
failure.

## Second defect this round exposed (the important one)
`worker-output.txt` for this round contains **18 characters**:

    TIMEOUT after 900s

The driver used `subprocess.run(capture_output=True)`, which buffers until the
child exits. A timeout therefore discarded **everything** the worker said —
16 minutes of URL probes and reasoning, gone with no record. A failure that
erases its own evidence is the worst kind: the next round cannot learn from it.

## Fixes applied
1. `sh()` now streams stdout to `runtime/loop/_dispatch.log` line-by-line while
   the child runs, so a timeout preserves partial output.
2. Scope cut from 6 classes to 2 (`--classes`, default 2).
3. Budget discipline added to the prompt: ~4 minutes, write the file as the
   FIRST action after one complete item, do NOT read the codebase.
4. Default timeout lowered 900 -> 600s so a stuck round costs less.

## Lesson
Tell the worker what NOT to read. A brief that says "read the gate to learn the
rules" is read as licence to spend the entire budget doing exactly that.
