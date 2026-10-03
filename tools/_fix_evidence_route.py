"""Route kind=evidence into the class page too.

Second instance of the SAME defect, found by the same check that caught
test/variant: 92 promoted items across 48 classes are absent from every
generated page, and every one of them is kind=evidence.

`evidence` has no destination in the kind -> section table, exactly as `test`
had none. The rows are gated and promoted; the projection simply has nowhere to
put them. That is worse than losing them -- the corpus holds knowledge that the
domain tree denies by omission, and a reader of the page concludes it does not
exist.

Where they belong: `evidence` items are what makes a technique PROVABLE, so they
render alongside Detection (the observable) rather than in a section of their
own. Detection already takes kind=signal.

Idempotent: no-ops when the edit is already present, and compiles the result.
"""
import io

P = "tools/taxonomy/build_taxonomy.py"
src = io.open(P, encoding="utf-8").read()

old = '        "Detection": _fmt(_items(con, cid, "signal")),\n'
new = ('        # `evidence` is what makes a technique PROVABLE and belongs with the\n'
       '        # observable. Without a route, 92 promoted items across 48 classes were\n'
       '        # rendered nowhere -- knowledge the corpus holds and the page denies.\n'
       '        "Detection": _fmt(_items(con, cid, "signal") + _items(con, cid, "evidence")),\n')

if new in src and old not in src:
    print("already applied")
elif old not in src:
    raise SystemExit("ANCHOR NOT FOUND:\n%s" % old)
else:
    src = src.replace(old, new, 1)
    print("patched Detection := signal + evidence")

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok")