# HANDOFF PROTOCOL — WKS research loop

If OpenCode is unavailable, blocked, or produces nothing usable, the loop does
not stop and does not degrade into fabricated output. It degrades into this
protocol. Every step is a command; nothing here needs judgement to execute.

## 0. STATE — where everything lives
```
WKS_ROOT            C:/Users/Administrator/.hermes/cyber   (native path required)
corpus              db/wks.db          (ONE db: wks/ knowledge + orch/ work)
intake              research/incoming/<name>.json          (+ `// COMPLETE <n>` last line)
loop config         runtime/loop/LOOP.json
rubric              runtime/loop/RUBRIC.json
score history       runtime/loop/SCORES.jsonl             (append-only)
round artifacts     runtime/loop/rounds/round-NN/{prompt,worker-output,gate-dry,gate-real,report}.md
worker brief        runtime/loop/WORKER_BRIEF.md
audit log           E:/bugbounty/cyber-reorg-log.md
backups             db/wks-pre-*.db  (taken before every mutating cycle)
```

## 1. WHEN OPENCODE IS UNAVAILABLE — the ordered fallback
Run these in order. Stop at the first that produces evidence.

1. **Hermes in-process executor** (no external CLI needed, already proven):
   `python -m orch.cli run --execute --max-tasks 6 --label <label>`
   It fetches live sources, extracts spans, re-verifies them, and ingests
   through the real gate. This is the default, and it is what OpenCode
   supplements rather than replaces.

2. **Native autonomous researcher** (the loop's own priority order):
   `python -m wks.cli cycle --max-items 5`
   `python -m orch.cli supervise --cycles 3`

3. **Delegated subagents** (when a human session is available): dispatch one
   specialist per class using `runtime/loop/WORKER_BRIEF.md` verbatim as the
   brief. Never let a subagent write the db.

4. **Manual intake**: a human drops a JSON file into `research/incoming/` and
   runs the acceptance test. This is the floor — the loop still works.

**Never** hand-write items into `db/wks.db`. The gate is the only writer.

## 2. ACCEPTANCE TEST — every round, no exceptions
```
cd C:/Users/Administrator/.hermes/cyber
python -m wks.ingest research/incoming/<file>.json --dry     # read the verdict
python -m wks.ingest research/incoming/<file>.json           # commit
python eval/test_gate_refuses_fabrication.py                  # gate still refuses
python eval/score_rubric.py                                   # what moved
```
A round is only "complete" when `report.md` exists in its round dir with the
worker exit code, the gate verdict, and the promoted/held counts.

## 3. HANDOFF PACKET — what to leave the next operator
Write `runtime/loop/HANDOFF-<n>.md` containing:
- last committed rubric total + the `SCORES.jsonl` line that proves it
- the failing criteria verbatim, with their evidence dicts
- the exact next command(s), in order, copy-pasteable
- db backup path taken before the last mutating run
- any KNOWN_GAPS emitted by `test_gate_refuses_fabrication.py` (these are real
  weaknesses; do not delete them to make a run look green)

## 4. RULES THAT SURVIVE ANY HANDOFF
1. Gate thresholds are never lowered to buy volume: MIN_PUBLISHER_HOSTS=2,
   MIN_SOURCES=2, MIN_CLAIM_CHARS=40, MIN_BODY_CHARS_SUPPORTED=200.
2. `--no-verify` exists only to be abused; a worker may never use it.
3. One item needs TWO INDEPENDENT PUBLISHER ORGS. learn.microsoft.com ==
   microsoft.com. Two pages of one site is one publisher.
4. Aggregator feeds (bugbountydaily RSS etc.) are DISCOVERY ONLY — cite the
   linked article.
5. A 404 citation is a MOVED page, not a fabrication; resolve it before
   dropping the item.
6. Report only numbers re-derived from the db. Never carry a number forward
   from a previous report.
7. If a scorer criterion errors, that is a FAIL with the error recorded — never
   a silent PASS and never an omitted criterion.

## 5. KNOWN GAPS AS OF 2026-10-04 (carried forward honestly)
- **GATE-ENTAILMENT**: the gate verifies a quote EXISTS on the cited page and
  that two publishers are independent. It does NOT verify the quote SUPPORTS the
  claim's mechanism. Measured: two verbatim-but-definitional quotes promote a
  mechanism claim at score ~0.80 (`test_gate_refuses_fabrication.py` case F2).
  Closing this needs a claim/quote entailment component that does not exist yet.
- **CLAIM-SHARPENESS**: `claimcheck` detects truncation, not vagueness, by
  design. 83 auto/harvest items carry templated topic claims under 90 chars.
  rubric rs3 measures this; it is a corpus gap, not a gate failure.
- **MOBILITY**: OpenCode is present (v1.18.34) with free models, so the two-agent
  loop is live. If `opencode run` starts failing (auth, quota, network), fall
  back per §1 without changing any other setting.