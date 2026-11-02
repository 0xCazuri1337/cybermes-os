"""Fix the kind -> section routing in build_taxonomy.py.

MEASURED DRIFT: 72 promoted items, 55 rendered. All 17 missing were kind=test
(9) and kind=variant (8) -- `rendered_of_this_kind=0/N` for every one, so the
generator had NO route for those kinds. The db rows are fine; the projection
drops them, which is the "a generated page can drift out of the tree silently"
failure: the corpus knows things the page denies by omission.

Two defects, both real:

  D1  "Validation" is fed from kind `validation` ONLY. Kind `test` -- which is
      how the earlier wave filed 148 proof-of-exploitation items, and how the
      children were told to file this wave -- had no route, so every promoted
      `test` item was invisible. `test` items ARE validation guidance.

  D2  "Variations" is `_fmt(bypass) or _fmt(variant)`. That `or` means a class
      holding even ONE bypass item renders its variants NOWHERE: the bypass list
      is non-empty, so the variant list is never computed. smuggling has both,
      and all 3 of its promoted variants were dropped by this alone.

Fixes:
  * Validation := validation + test
  * Variations := bypass + variant (concatenated, not `or`)

Idempotent: asserts the OLD text is present before replacing, and compiles.
"""
import io

P = "tools/taxonomy/build_taxonomy.py"
src = io.open(P, encoding="utf-8").read()

pairs = [
    # D2: concatenate instead of `or`
    ('        "Variations": _fmt(_items(con, cid, "bypass")) or _fmt(_items(con, cid, "variant")),\n',
     '        # `or` HID every variant item in any class that also holds a bypass:\n'
     '        # smuggling has both, so all 3 of its promoted variants were dropped.\n'
     '        "Variations": _fmt(_items(con, cid, "bypass") + _items(con, cid, "variant")),\n'),
    # D1: route kind=test into Validation as well
    ('        "Validation": _fmt(_items(con, cid, "validation")),\n',
     '        # `test` is proof-of-exploitation guidance and belongs here. Without\n'
     '        # this, every promoted kind=test item was dropped from the page.\n'
     '        "Validation": _fmt(_items(con, cid, "validation") + _items(con, cid, "test")),\n'),
]

for old, new in pairs:
    if new in src and old not in src:
        print("already applied: %s" % old.strip()[:52])
        continue
    if old not in src:
        raise SystemExit("ANCHOR NOT FOUND:\n%s" % old)
    src = src.replace(old, new, 1)
    print("patched: %s" % old.strip()[:52])

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok")