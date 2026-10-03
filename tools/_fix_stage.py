"""Repair ht_stage.py's audit-key block.

The `patch` tool re-indents Python on this host (reproduced repeatedly), so the
block is rewritten from a script instead of patched again. Two defects are fixed:

  1. the lookup was keyed on (class_id, page), so an audit FAIL on one quote was
     masked by a PASS on another quote from the SAME page -- measured on 26
     pages. Key now includes the claim's leading span.
  2. the surrounding indentation was mangled by repeated patching; the whole
     function body is rewritten here so the file is syntactically valid again.
"""
import io
import re

P = "tools/ht_stage.py"
src = io.open(P, encoding="utf-8").read()

# --- 1. repair the mangled lookup block -------------------------------------
old_block = re.search(
    r"    # The audit key must include the QUOTE.*?passed_pages = collections\.Counter\(k for k in ok\)\n",
    src, re.S)
new_block = '''    # The audit key must include the QUOTE, not just (class, page).
    # MEASURED: 26 pages carry more than one audited quote, and keying on
    # (class_id, page) let a FAIL on one quote be masked by a PASS on its
    # page-mate -- the ssti client-side-template item was refused by D2 and
    # still staged. The gate caught it independently (OFF_CLASS_TOPIC), which
    # is luck, not design: a masked FAIL that nothing else catches is a
    # silently unchecked item. Key on the claim's own leading span.
    ok = set()
    for r in audit:
        if r["verdict"] == "PASS":
            ok.add((r["class_id"], r["page"], (r.get("claim") or "")[:80]))
'''
if old_block:
    src = src[:old_block.start()] + new_block + src[old_block.end():]
    print("repaired the audit-key block")
else:
    print("lookup block not found; leaving as-is")

# --- 2. repair the mangled membership test ----------------------------------
bad = re.search(
    r"        key = \(r\[\"class_id\"\], page, claim\[:80\]\)\s*\n"
    r"(?:\s*if key not in ok:.*?\n\s*continue\s*\n?)", src)
good = ('        key = (r["class_id"], page, claim[:80])\n'
        '        if key not in ok:\n'
        '            refused.append((r["class_id"], page, "audit FAIL"))\n'
        '            continue\n')
if bad:
    src = src[:bad.start()] + good + src[bad.end():]
    print("repaired the membership test")
else:
    print("membership test not found; leaving as-is")

# --- 3. drop the now-unused passed_pages counter ---------------------------
src = re.sub(r"(?m)^.*passed_pages = .*\n", "", src)

io.open(P, "w", encoding="utf-8").write(src)
compile(src, P, "exec")
print("lint ok")