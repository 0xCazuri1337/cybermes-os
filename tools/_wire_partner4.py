"""Insert partner2 into ht_stage at the correct place: BEFORE the sources list
is closed, i.e. before the line ending `part}]`.

The previous attempt asserted on `part})`, which is the shape when the partner
dict is the LAST element of the list. Here the list is written as
`sources = [{...}, {...part}]` so the closing character is `}]`. Getting that
wrong is why the guard fired -- which is the point of the guard: a write that
silently lands in the wrong place compiles fine and changes behaviour.

Insertion point: immediately after the line containing `"quote": part}]`,
which is inside the literal, so the new dict becomes a third element.
"""
import io

P = "tools/ht_stage.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

target = None
for i, ln in enumerate(lines):
    if '"quote": part}]' in ln:
        target = i
        break
if target is None:
    raise SystemExit('the `"quote": part}]` line was not found')
print("inserting after line %d: %s" % (target + 1, lines[target].strip()))

NEW = ['',
       '        # A brand-new class carries a SECOND seeded partner on a different',
       '        # registrable org. Without it a reference-doc item cannot reach',
       '        # MIN_PUBLISHER_HOSTS: CWE alone is one publisher, so every',
       '        # privesc item was refused with "only 1 real publisher org(s)".',
       '        # `ht_brief` carries it through the brief; both halves are needed.',
       '        p2 = r.get("partner2_quote_already_verified")',
       '        if p2 and r.get("partner2_url") and r["partner2_url"] != r["partner_url"]:',
       '            sources.append({',
       '                "url": r["partner2_url"], "source_type": "research",',
       '                "host": r["partner2_url"].split("/")[2],',
       '                "publisher": r.get("partner2_org") or org_of(r["partner2_url"]),',
       '                "quote": p2})']

lines[target + 1:target + 1] = NEW
src = "\n".join(lines)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("inserted %d lines; lint ok" % len(NEW))