"""Print the per-task child summaries from a spilled delegate_task result file."""
import json
import re
import sys

P = r"C:\Users\Administrator\AppData\Local\hermes\cache\spillover\f19a6b3e-f933-4ec9-b722-2a50124af160.txt"
raw = open(P, encoding="utf-8").read()
d = json.loads(raw)
for r in d["results"]:
    print("=" * 70)
    print("TASK %s  status=%s  schema_valid=%s" %
          (r.get("task_index"), r.get("status"), r.get("schema_valid")))
    if r.get("schema_errors"):
        print("SCHEMA ERRORS:", r["schema_errors"])
    s = r.get("summary", "")
    # keep it tight: the verdict lines matter more than the prose
    for line in s.splitlines():
        if re.search(r"submitted=|chains_written|chain_errors|fp_case|REJECT|QUOTE_NOT_"
                     r"FOUND|COMPLETE|items written|\*\*\d+ item|rejected|fp_case rows|"
                     r"chains", line):
            print("   ", line[:200])