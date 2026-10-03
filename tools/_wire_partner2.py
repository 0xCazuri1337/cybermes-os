"""Carry partner2 through ht_brief and accept it in ht_stage.

`ht_brief.py` flattens a packet into one row per quote and copies only
`partner`, so the second seeded partner never reached the stager -- and the
stager then refused every privesc item with "only 1 real publisher org(s)". The
information existed in the packet and was dropped in transit, which is the same
class of defect as the SECTIONS-keyed-on-the-wrong-name bug: correct data, wrong
wiring, silent omission.
"""
import io

# --- 1. ht_brief: emit partner2 -------------------------------------------
P1 = "tools/ht_brief.py"
s = io.open(P1, encoding="utf-8").read()
old = '''                    "partner_url": e["partner"]["url"],
                    "partner_org": e["partner"]["org"],
                    "partner_quote_already_verified": e["partner"]["quote"],'''
new = '''                    "partner_url": e["partner"]["url"],
                    "partner_org": e["partner"]["org"],
                    "partner_quote_already_verified": e["partner"]["quote"],
                    "partner2_url": (e.get("partner2") or {}).get("url"),
                    "partner2_org": (e.get("partner2") or {}).get("org"),
                    "partner2_quote_already_verified":
                        (e.get("partner2") or {}).get("quote"),'''
if old in s:
    s = s.replace(old, new, 1)
    compile(s, P1, "exec")
    io.open(P1, "w", encoding="utf-8").write(s)
    print("patched ht_brief: partner2 emitted")
else:
    print("ht_brief: anchor not found (already patched?)")

# --- 2. ht_stage: accept partner2 -----------------------------------------
P2 = "tools/ht_stage.py"
t = io.open(P2, encoding="utf-8").read()
anchor = '''            {"url": r["partner_url"], "source_type": "research",
            "host": r["partner_url"].split("/")[2],
            "publisher": r.get("partner_org") or org_of(r["partner_url"]),
            "quote": part})'''
# find the real 2-line-then-close form inside the sources list literal
import re
m = re.search(r'            \{"url": r\["partner_url"\], "source_type": "research",\n'
              r'            "host": r\["partner_url"\]\.split\("/"\)\[2\],\n'
              r'            "publisher": r\.get\("partner_org"\) or org_of\(r\["partner_url"\]\),\n'
              r'            "quote": part\}\}', t)
if m:
    add = m.group(0) + '''

        # A brand-new class carries a SECOND seeded partner on a different
        # registrable org. Without it a reference-doc item cannot reach
        # MIN_PUBLISHER_HOSTS: CWE alone is one publisher. `ht_brief` carries it
        # through; without BOTH halves the privesc items were refused.
        p2 = r.get("partner2_quote_already_verified")
        if p2 and r.get("partner2_url") and r["partner2_url"] != r["partner_url"]:
            sources.append({
                "url": r["partner2_url"], "source_type": "research",
                "host": r["partner2_url"].split("/")[2],
                "publisher": r.get("partner2_org") or org_of(r["partner2_url"]),
                "quote": p2})'''
    t = t[:m.start()] + add + t[m.end():]
    compile(t, P2, "exec")
    io.open(P2, "w", encoding="utf-8").write(t)
    print("patched ht_stage: partner2 accepted")
else:
    print("ht_stage: partner anchor not found")