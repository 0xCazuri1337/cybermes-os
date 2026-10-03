# R31 — the corpus has more than one writer

Measured 2026-10-02, recon mastery cycle. A "w12" wave ingested **90 items
across 18 web classes at 22:02–22:05 local**, from `research/incoming/w12_*.json`,
while an operator was auditing that same corpus. The item count went
1111 -> 1196 and 5 more rows moved to `superseded` with no command in the audit
session producing either.

Neither of the three cron jobs did it — all were `paused` and the last had run
at 15:26 — and no subagent in the audit's own wave did it. It was a separate
session or a resumed loop working the same tree.

## Why this is a rule and not an incident note

An audit that re-reads a mutating corpus produces numbers that are true only of
an instant. Every "measured" claim in `research/recon/` became stale inside an
hour, and `tools/recon_verify_children.py` went from PASS to FAIL with no change
to its own logic — because 3 coverage totals no longer matched. A verifier that
fails because the world moved is indistinguishable from a broken verifier, which
is the same trap as a dead filter.

## The invariant

    A measurement is only valid if the corpus did not change while it was taken.

**How it is checked.** Snapshot the row counts and a content hash before a
measurement, compare after, and treat any drift as a failed run rather than a
result:

```python
from wks.readonly import ro
def fingerprint(con):
    return dict(con.execute(
        "SELECT (SELECT count(*) FROM item WHERE status='active'),"
        "       (SELECT count(*) FROM source),"
        "       (SELECT count(*) FROM item)"))
# before = fingerprint(con)   ... measure ...
# assert fingerprint(con) == before, "corpus moved during the measurement"
```

`db/wks-pre-resynth-*.db` and the `.bak-*` files are the existing precedent, and
this cycle used them for exactly this reason — they are what made the w12 wave
detectable rather than invisible.

**On failure.** Do not report the number. Re-take it against a fresh snapshot, or
explicitly label it "as of <snapshot mtime>" so a reader knows which instant it
describes. Never silently merge a measurement taken before a write with a
conclusion drawn after it.

## What this cycle did about it

Nothing was rolled back. The w12 items are real, evidenced work from another
session, and deleting another session's output to make an audit look clean would
be worse than the drift. Instead:

- the corpus was verified intact against the pre-session snapshot
  (`item_key + claim + disproof` byte-identical, all 8 table counts equal)
- the 90 new items were measured on their own terms: **80 on-topic, 5 orphan,
  5 held** — and the 5 holds carry `OFF_CLASS_TOPIC` in `gate_reasons`

That last line is the actual proof that R29 is load-bearing: the w12 wave
ingested *after* the subject gate went live, and the gate refused 5 of its items
on arrival without being asked. A gate that only fires during an audit is an
audit; this one is a control.

## Standing recommendation

Before starting a measurement run on this corpus, record
`SELECT count(*), max(updated_at) FROM item` and compare it at the end. If
another writer is active, either coordinate or sandbox the run — `wks.readonly`
now exists so that "sandbox the run" is one call, and R30 is why.