"""Repair the over-indented membership test in ht_stage.py, by line surgery.

The `patch` tool re-indents Python on this host (reproduced repeatedly on this
file), so this edits by explicit line index rather than by pattern replacement.
Idempotent: re-running on an already-correct file is a no-op.
"""
import io

P = "tools/ht_stage.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

GOOD = [
    '        if key not in ok:',
    '            refused.append((r["class_id"], page, "audit FAIL"))',
    '            continue',
]

# find the line that starts the test, then the 'continue' that ends it
start = None
for i, ln in enumerate(lines):
    if ln.strip().startswith("if key not in ok:"):
        start = i
        break
if start is None:
    print("membership test not found; nothing to do")
else:
    end = start
    while "continue" not in lines[end]:
        end += 1
    # does the test already start at the right indent, right after a `key =` line?
    already_ok = (lines[start] == GOOD[0] and lines[start + 1] == GOOD[1]
                  and lines[start + 2] == GOOD[2])
    if already_ok:
        print("already correct; no change")
    else:
        print("rewriting lines %d-%d" % (start + 1, end + 1))
        print("  before: %r" % lines[start:start + 3])
        lines[start:end + 1] = GOOD
        print("  after : %r" % GOOD)

src = "\n".join(lines)
io.open(P, "w", encoding="utf-8").write(src)
compile(src, P, "exec")
print("lint ok")