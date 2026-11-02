"""Insert the partner2 acceptance into ht_stage by LINE INDEX.

The regex anchor failed because the literal spans lines 214-217 and my pattern
expected a different closing. Located by index instead, and the insert is
guarded: it refuses to write if the anchor lines are not what it expects.
"""
import io

P = "tools/ht_stage.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

# the partner dict literal: find its closing 'quote": part})' line
start = None
for i, ln in enumerate(lines):
    if '"url": r["partner_url"], "source_type": "research"' in ln:
        start = i
        break
if start is None:
    raise SystemExit("partner literal not found")
end = start
while '"quote": part}' not in lines[end]:
    end += 1
print("partner literal spans lines %d..%d" % (start + 1, end + 1))
assert lines[end].strip() == '"quote": part})', \
    "line %d is %r" % (end + 1, lines[end])

NEW = '''

        # A brand-new class carries a SECOND seeded partner on a different
        # registrable org. Without it a reference-doc item cannot reach
        # MIN_PUBLISHER_HOSTS: CWE alone is one publisher, so every privesc item
        # was refused with "only 1 real publisher org(s)". `ht_brief` carries it
        # through the brief; both halves are needed or neither works.
        p2 = r.get("partner2_quote_already_verified")
        if p2 and r.get("partner2_url") and r["partner2_url"] != r["partner_url"]:
            sources.append({
                "url": r["partner2_url"], "source_type": "research",
                "host": r["partner2_url"].split("/")[2],
                "publisher": r.get("partner2_org") or org_of(r["partner2_url"]),
                "quote": p2})'''.split("\n")

lines[end + 1:end + 1] = NEW
src = "\n".join(lines)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("inserted %d lines; lint ok" % len(NEW))