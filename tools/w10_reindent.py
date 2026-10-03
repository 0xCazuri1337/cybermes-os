"""Re-indent the FABRICATED branch in wks/ingest.py to the block's true level.

The `patch` tool re-indented the whole inserted block one level too deep (the
known patch-tool defect, now reproduced across four separate ticks). Python
accepts any deeper indent for a block, so it COMPILES -- which is exactly why
lint did not catch it and why it must be checked by reading the bytes.
"""
import io
import py_compile
import re
import sys

P = r"C:/Users/Administrator/.hermes/cyber/wks/ingest.py"
src = io.open(P, encoding="utf-8").read()
lines = src.split("\n")

# locate the branch
start = next(i for i, l in enumerate(lines)
             if l.strip() == 'if v == "FABRICATED":')
# find the end: the next line at the branch's own indent that is not blank
indent = len(lines[start]) - len(lines[start].lstrip())
end = next(i for i in range(start + 1, len(lines))
           if lines[i].strip() and (len(lines[i]) - len(lines[i].lstrip())) <= indent)
print("branch lines %d..%d  (branch indent=%d)" % (start + 1, end, indent))

body = lines[start + 1:end]
# every body line is one level too deep; the final `continue` was moved too
fixed = []
for l in body:
    fixed.append(l[4:] if l.startswith("    ") else l)
new = lines[:start + 1] + fixed + lines[end:]

# the `continue` must sit at the branch indent, and the block must be uniform
out = "\n".join(new)
io.open(P, "w", encoding="utf-8").write(out)

chk = out.split("\n")
s2 = next(i for i, l in enumerate(chk) if l.strip() == 'if v == "FABRICATED":')
for i in range(s2, min(s2 + 40, len(chk))):
    print("%4d|%s" % (i + 1, chk[i]))

py_compile.compile(P, doraise=True)
print("\nCOMPILES OK")
src2 = io.open(P, encoding="utf-8").read()
assert "row = con.execute(" in src2, "patch lost the dedupe lookup"
assert "INSERT INTO conflict" in src2, "patch lost the insert"
print("dedupe lookup present:", src2.count("row = con.execute("))
print("inserts present:", src2.count("INSERT INTO conflict"))