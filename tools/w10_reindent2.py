"""Re-indent the FABRICATED branch to 12 spaces (the branch itself sits at 8).

The `patch` tool re-indented the inserted block one level too deep (known
defect, fourth reproduction). Python accepts any deeper indent so it COMPILES
and lint stays green -- the only reliable check is reading the bytes, which is
exactly what this does.
"""
import io
import py_compile

P = r"C:/Users/Administrator/.hermes/cyber/wks/ingest.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

start = next(i for i, l in enumerate(lines) if l.strip() == 'if v == "FABRICATED":')
indent = len(lines[start]) - len(lines[start].lstrip())
assert indent == 8, "branch is not at indent 8: %d" % indent
end = next(i for i in range(start + 1, len(lines))
           if lines[i].strip() and (len(lines[i]) - len(lines[i].lstrip())) <= indent)

body = lines[start + 1:end]
stripped = [(l[4:] if l.startswith("    ") else l) for l in body]
while stripped and not stripped[-1].strip():
    stripped.pop()
tail = []
if stripped and stripped[-1].strip() == "continue":
    tail = ["        continue"]
    stripped = stripped[:-1]
levels = {len(l) - len(l.lstrip()) for l in stripped if l.strip()}
assert levels == {12}, "block not uniform at 12: %s" % sorted(levels)

out = lines[:start + 1] + stripped + tail + lines[end:]
io.open(P, "w", encoding="utf-8").write("\n".join(out))

final = "\n".join(out).split("\n")
for i, l in enumerate(final[max(0, start - 3):start + 44], max(0, start - 2)):
    print("%4d|%s" % (i, l))
py_compile.compile(P, doraise=True)
src = io.open(P, encoding="utf-8").read()
print("\nCOMPILES OK")
print("dedupe lookup count:", src.count("SELECT id, resolution FROM conflict"))
print("insert count:", src.count("INSERT INTO conflict"))