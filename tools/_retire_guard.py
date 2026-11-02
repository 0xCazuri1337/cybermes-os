"""Make the retired htb_merge_domains exit cleanly instead of crashing.

It now sets `path = None` and then calls `open(path, "w")`, which raises
TypeError. That is honest -- it cannot write -- but a tool that crashes is
indistinguishable from a tool that is broken, and the next person wastes time on
the traceback. It should print its report and exit 0 having written nothing.

Turns the write into a guard: report, then return.
"""
import io

P = "tools/htb_merge_domains.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

target = None
for i, ln in enumerate(lines):
    if 'path = None  # RETIRED: no file is written' in ln:
        target = i
        break
if target is None:
    raise SystemExit("the RETIRED marker is not in the file")

# find the `with open(path, "w"...)` line and guard it
w = None
for i in range(target, min(target + 30, len(lines))):
    if 'with open(path, "w"' in lines[i]:
        w = i
        break
if w is None:
    raise SystemExit("the write line was not found after the RETIRED marker")

indent = " " * (len(lines[w]) - len(lines[w].lstrip()))
lines[w:w] = [
    indent + "if path is None:",
    indent + '    print("RETIRED: %s is not written; the class pages under"'
    % 'domains/{web,network}/<class>/knowledge/CLASS.md',
    indent + '          "are the canonical home. This tool reports only.")',
    indent + "    return",
]
src = "\n".join(lines)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("guarded the write at line %d; lint ok" % (w + 1))