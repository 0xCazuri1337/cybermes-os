import json
import re
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "tools")
import ht_fetch
from wks import verify_quotes as V

t = ht_fetch.get("pentesting-web/sql-injection/README.md", {})[0]
print("backslash+newline occurrences in the RAW source markdown:",
      len(re.findall(r"\\\n", t)))

d = json.load(open("research/ht_packets_web.json", encoding="utf-8"))
bad = 0
for cid, entries in d["packets"].items():
    for e in entries:
        for x in e["quotes"]:
            if "\\" in x["quote"]:
                bad += 1
                ok = V.find_quote(t if "sqli" in cid else "", x["quote"])
                print("  class=%-6s verifies_on_that_page=%s" % (cid, ok))
print("quotes containing a backslash:", bad)

# Defect B: which pages are still misrouted by v3 scoring?
print()
xw = json.load(open("research/ht_crosswalk.json", encoding="utf-8"))
susp = [p for p in xw["MATCHED"]
        if p["cls"] in ("idor", "ssti", "xxe", "internal_recon", "cmd", "session")
        and p["section"] in ("generic-methodologies-and-resources", "linux-hardening")]
print("pages mapped across SECTION boundaries (class in one section, page in another):")
for p in sorted(susp, key=lambda p: (p["cls"], p["rel"])):
    print("  %-18s %-42s %s" % (p["cls"], p["section"], p["rel"][:66]))