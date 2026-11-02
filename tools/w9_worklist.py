"""Build the wave-9 work list: registered-but-uncited sources + the exclusion
list of every host already in the corpus, so host reuse is visible rather than
silent. Read-only.
"""
import json
import os
import sys

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
os.environ.setdefault("WKS_ROOT", ROOT)
from wks import config, store  # noqa: E402
from wks import research_sources as RS  # noqa: E402

con = store.open_db(create=False)
cited = {r[0] for r in con.execute("SELECT DISTINCT host FROM source").fetchall()}
urls = {r[0] for r in con.execute("SELECT url FROM source").fetchall()}
print("CITED HOSTS (%d):" % len(cited))
print(json.dumps(sorted(cited), indent=0))

registered = []
for attr in dir(RS):
    if attr.startswith("_"):
        continue
    v = getattr(RS, attr)
    if isinstance(v, (list, tuple, set)):
        registered.extend([x for x in v if isinstance(x, str)])

print("\nresearch_sources entries:", len(registered))
fresh = [u for u in registered if u not in urls]
print("registered URLs not yet cited:", len(fresh))
for u in fresh:
    print("  ", u)

print("\n--- taxonomy seed hosts (NORMATIVE, satisfies the 2-host gate) ---")
try:
    from wks import taxonomy as TX
    seed = getattr(TX, "_SEED", None)
    if isinstance(seed, dict):
        hosts = set()
        for v in seed.values():
            if isinstance(v, (list, tuple)):
                for u in v:
                    if isinstance(u, str) and "://" in u:
                        hosts.add(u.split("/")[2].lower().removeprefix("www."))
        print("seed urls:", sum(len(v) for v in seed.values()
                                if isinstance(v, (list, tuple))))
        print("seed hosts already cited:",
              sorted(h for h in hosts if h in cited))
        print("seed hosts NOT yet cited:",
              sorted(h for h in hosts if h not in cited))
except Exception as e:
    print("taxonomy seed read failed:", type(e).__name__, e)

con.close()