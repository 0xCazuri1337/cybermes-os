# Running parallel hunt lanes without losing work

Use when a hunt fans out across several host groups, or delegates lanes to
subagents. The failure this prevents: **a lane dies mid-run and its work vanishes**,
because a sweep script buffers every row and only writes at the end.

## Rule: flush incrementally, always

A lane killed at 80% must not lose the 80%. Write each row as it completes, and
write the sidecar state (`scored`, `resolved`, `queue`) to disk **before** starting the
HTTP phase, so a dead lane leaves a resumable artifact rather than nothing.

```python
# BAD — a kill here loses everything
rows = [probe(h) for h in hosts]
json.dump(rows, out)          # never reached

# GOOD — resumable, and the JSON is readable while the lane still runs
with open(out, "w") as f:
    json.dump({"started": len(hosts)}, f)
for i, h in enumerate(hosts, 1):
    row = probe(h)
    rows.append(row)
    if i % 10 == 0:
        json.dump({"rows": rows, "done": i}, f, indent=2)   # flush
```

## Rule: split discovery from probing

Passive phases (DNS resolution, scoring, queue building) are cheap, deterministic and
interruptible. HTTP probing is expensive and rate-limited. Persist the queue first:

```
recon/lane_scored.json      # hostname -> signal score, from passive signals only
recon/lane_resolved.json    # hostname -> resolves? (no HTTP yet)
recon/lane_queue.json       # the ordered work list
evidence/lane_result.json   # HTTP results, flushed incrementally
```

A lane killed during probing then costs a rerun of a small, well-defined list instead
of the whole discovery phase — and the rerun starts from the queue, not from recon.

## Rule: a killed lane is not a result

If a delegated lane reports completion but its output artifact is missing, verify the
file before believing either the report or the failure. A delegation summary describes
intent; the artifact on disk is the evidence.

```bash
for f in LANE_A.md LANE_B.md laneA.json laneB.json; do
  [ -f "$f" ] && echo "  $f  $(wc -c < "$f") bytes" || echo "  $f  MISSING"
done
```

## Rule: bind long lanes to a time budget, and steer on overrun

A subagent that overruns its budget silently costs more than one that fails fast.
Give it an explicit budget and the wrap-up instruction up front, and steer it to write
its report when it runs long — the steer text should say *write the report now with the
evidence you have*, and must include the verdict conventions so the child cannot
inflate a weak lead to have something to report.

Also pass the **already-closed dead ends** into every child prompt. Re-deriving a
refuted lead costs the lane its whole budget, and a child that independently
re-derives your conclusions cannot be used to check them.

## Recovery order after a lane dies

1. Confirm what survived on disk (queue, partial rows) before re-dispatching.
2. Re-run the **narrowest** missing piece from the persisted queue.
3. Never re-dispatch the whole lane if the queue is intact — that repeats the loss.