"""Move the 5 privesc rows OUT of taxonomy_spec.CLASSES.

The spec's CLASSES list is for classes with NO db row: `taxonomy_write.py`
renders those under `skills/<domain>/topics/<slug>.md` with HYPHENATED names.
A class that IS registered in the db gets its page from `wks.domains.class_rel`,
which is the ONE function every writer calls and which produces
`skills/<domain>/<specialization>/<class_id>` with the UNDERSCORED id.

So registering the 5 classes in the db AND adding them to the spec produced two
different homes: the generator wrote hyphenated topic stubs while the tree check
looked for the underscored class directory, and reported 5 "missing" classes.
Correct fix: the db registration was right and the spec rows are wrong.

Verified by the generator's own comment: "CLASSES row with no db class, so it
renders under the domain's topics/".
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

cstart = cend = None
for i, ln in enumerate(lines):
    if ln.strip() == "CLASSES = [":
        cstart = i
        break
depth = 0
for i in range(cstart, len(lines)):
    depth += lines[i].count("[") - lines[i].count("]")
    if depth == 0 and i > cstart:
        cend = i
        break
print("CLASSES spans lines %d..%d" % (cstart + 1, cend + 1))

drop = set()
for path in PATHS:
    for i in range(cstart, cend):
        if '"%s"' % path in lines[i]:
            j = i
            while j < cend and not lines[j].rstrip().endswith("),"):
                j += 1
            for k in range(i, j + 1):
                drop.add(k)
            print("  - dropped %s" % path.rsplit("/", 1)[-1])
            break

out = [ln for k, ln in enumerate(lines) if k not in drop]
src = "\n".join(out)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("removed %d row(s); lint ok" % len(drop))

# also remove the topic stubs the generator wrote for them
import os
stubs = [
    "skills/network/topics/active-directory/windows-privesc-token.md",
    "skills/network/topics/active-directory/windows-privesc-hijack.md",
    "skills/network/topics/active-directory/windows-privesc-service.md",
    "skills/network/topics/internal-network/linux-privesc.md",
    "skills/network/topics/internal-network/container-escape.md",
]
for s in stubs:
    if os.path.exists(s):
        os.remove(s)
        print("  - removed stub %s" % s)