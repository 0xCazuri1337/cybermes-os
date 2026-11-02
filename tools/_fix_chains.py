"""Remove the 5 privesc rows that attempt #1 inserted into CHAINS.

By line surgery, exactly like _fix_spec3: locate each row by its own path string,
delete from that line to the line that closes its tuple, and verify the file still
compiles before writing. CHAINS must hold chains, not class definitions -- a
class-shaped tuple there renders as a chain page and is invisible to the drift
check that is supposed to catch exactly this.
"""
import io

P = "tools/taxonomy/taxonomy_spec.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

PATHS = [
    "network/active-directory/windows-privesc-token.md",
    "network/active-directory/windows-privesc-hijack.md",
    "network/active-directory/windows-privesc-service.md",
    "network/internal-network/linux-privesc.md",
    "network/internal-network/container-escape.md",
]

# Only remove occurrences inside the CHAINS list, so the CLASSES copies stay.
cstart = cend = None
for i, ln in enumerate(lines):
    if ln.strip() == "CHAINS = [":
        cstart = i
        break
if cstart is None:
    raise SystemExit("CHAINS = [ not found")
depth = 0
for i in range(cstart, len(lines)):
    depth += lines[i].count("[") - lines[i].count("]")
    if depth == 0 and i > cstart:
        cend = i
        break
print("CHAINS spans lines %d..%d" % (cstart + 1, cend + 1))

removed = 0
drop = set()
for path in PATHS:
    for i in range(cstart, cend):
        if '"%s"' % path in lines[i]:
            # walk forward to the line that closes the tuple
            j = i
            while j < cend and not lines[j].rstrip().endswith("),"):
                j += 1
            for k in range(i, j + 1):
                drop.add(k)
            removed += 1
            print("  - dropped line %d..%d  %s" % (i + 1, j + 1, path.rsplit("/", 1)[-1]))
            break

if removed:
    out = [ln for k, ln in enumerate(lines) if k not in drop]
    src = "\n".join(out)
    compile(src, P, "exec")
    io.open(P, "w", encoding="utf-8").write(src)
print("removed %d misplaced row(s); lint ok" % removed)