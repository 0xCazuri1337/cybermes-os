"""Extract every command line a child reported running, to find who re-ingested
the OLD files (xss.json, idor.json, race.json, ssrf.json, graphql.json,
w5-fp-web.json) 4-7 times each.

Reads the spilled delegate_task result file and prints every line that looks
like a shell command, grouped per task. Also prints any mention of those
filenames.
"""
import json
import re

P = r"C:\Users\Administrator\AppData\Local\hermes\cache\spillover\f19a6b3e-f933-4ec9-b722-2a50124af160.txt"
d = json.loads(open(P, encoding="utf-8").read())

OLD = ["xss.json", "idor.json", "race.json", "ssrf.json", "graphql.json",
       "w5-fp-web.json"]

for r in d["results"]:
    s = r.get("summary", "")
    print("=" * 72)
    print("TASK %s" % r.get("task_index"))
    cmds = [ln.strip() for ln in s.splitlines()
            if re.search(r"(wks\.ingest|wks\.reconcile|wks\.fp|wks\.cli|tools/)", ln)]
    for c in cmds[:40]:
        print("   %s" % c[:190])
    hits = [ln.strip() for ln in s.splitlines() if any(o in ln for o in OLD)]
    if hits:
        print("   --- OLD-FILE MENTIONS ---")
        for h in hits[:20]:
            print("   * %s" % h[:190])