"""Shift the whole FABRICATED branch left by 4 spaces, uniformly.

The `patch` tool re-indented the block one level too deep (known defect, fourth
reproduction). Because the shift is UNIFORM the internal nesting is preserved and
the result is correct at every level. Python accepts any deeper indent so the
defect compiled and lint stayed green -- proof that reading the bytes is the
only reliable check.
"""
import io
import py_compile

P = r"C:/Users/Administrator/.hermes/cyber/wks/ingest.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

start = next(i for i, l in enumerate(lines) if l.strip() == 'if v == "FABRICATED":')
base = len(lines[start]) - len(lines[start].lstrip())
end = next(i for i in range(start + 1, len(lines))
           if lines[i].strip() and (len(lines[i]) - len(lines[i].lstrip())) <= base)

body = lines[start + 1:end]
for l in body:
    assert l.startswith("    ") or not l.strip(), "line not dedentable: %r" % l
shifted = [l[4:] if l.startswith("    ") else l for l in body]

out = lines[:start + 1] + shifted + lines[end:]
text = "\n".join(out)
io.open(P, "w", encoding="utf-8").write(text)

final = text.split("\n")
s = next(i for i, l in enumerate(final) if l.strip() == 'if v == "FABRICATED":')
for i, l in enumerate(final[s:min(s + 46, len(final))], s + 1):
    print("%4d|%s" % (i, l))

py_compile.compile(P, doraise=True)
print("\nCOMPILES OK")
print("branch indent:", len(final[s]) - len(final[s].lstrip()))
print("first body line indent:",
      len(final[s + 1]) - len(final[s + 1].lstrip()))
src = io.open(P, encoding="utf-8").read()
print("dedupe lookup:", src.count("SELECT id, resolution FROM conflict"))
print("insert:", src.count("INSERT INTO conflict"))