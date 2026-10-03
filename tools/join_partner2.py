"""Carry the new brief's partner2 onto the answers already written.

MEASURED: the children authored claims against `br_privesc.json`, which was
built before the two-org seeds existed, so those answer rows carry no
`partner2_*` fields. Re-running the children would waste the whole wave, because
the CLAIMS do not depend on the partner -- only the publisher arithmetic does.

So the partner fields are joined on the stable key (class_id, page, quote
prefix) rather than re-authored. The join is asserted: every answer row must
match exactly one new-brief row, and the quotes must be byte-identical, or the
merge refuses. Joining on a loose key would attach one class's partner quote to
another class's claim, which is precisely the kind of citation the gate exists
to catch -- and it would pass, because both quotes are individually valid.
"""
import io
import json

ANS = "research/ans_privesc.json"
NEW = "research/br_privesc2.json"
OUT = "research/ans_privesc2.json"

ans = json.load(open(ANS, encoding="utf-8"))
new = json.load(open(NEW, encoding="utf-8"))


def key(r):
    return (r["class_id"], r["hacktricks_page"], (r["QUOTE_VERBATIM"] or "")[:80])


newmap = {}
dupes = 0
for r in new:
    k = key(r)
    if k in newmap:
        dupes += 1
    newmap[k] = r
print("answers: %d   new brief: %d   distinct new keys: %d (dupes %d)"
      % (len(ans), len(new), len(newmap), dupes))

PARTNER_FIELDS = ["partner2_url", "partner2_org",
                  "partner2_quote_already_verified"]
merged = unmatched = 0
for r in ans:
    n = newmap.get(key(r))
    if not n:
        unmatched += 1
        continue
    # the join must be on the SAME quote, not merely the same class+page
    assert (n["QUOTE_VERBATIM"] or "") == (r["QUOTE_VERBATIM"] or ""), \
        "quote differs for %s -- refusing to merge" % (r["class_id"],)
    for f in PARTNER_FIELDS:
        if n.get(f) and not r.get(f):
            r[f] = n[f]
    if r.get("partner2_url"):
        merged += 1

print("rows given a second partner : %d" % merged)
print("rows with no new-brief match: %d" % unmatched)
assert unmatched == 0, "refusing to write: %d rows unmatched" % unmatched
assert merged == len(ans), "only %d of %d rows got partner2" % (merged, len(ans))

json.dump(ans, open(OUT, "w", encoding="utf-8"), indent=1)
print("wrote %s" % OUT)
print("  sample partner2:", ans[0].get("partner2_org"), "|",
      ans[0].get("partner2_url", "")[:58])