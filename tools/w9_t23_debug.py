"""Why did T23 promote nothing? Print the actual rejection reason per item
instead of guessing at the fixture.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="wks_t23dbg_")
os.environ["WKS_ROOT"] = SANDBOX
ROOT = Path(r"C:/Users/Administrator/.hermes/cyber")
sys.path.insert(0, str(ROOT))

from wks import ingest as wks_ingest, store  # noqa: E402

SRCS_A = [{"url": "https://portswigger.net/web-security/ssrf", "host": "portswigger.net",
           "publisher": "PortSwigger", "source_type": "docs",
           "quote": "SSRF (Server-Side Request Forgery) is an attack that can be used to trick a server into making requests on your behalf."},
          {"url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
           "host": "owasp.org", "publisher": "OWASP", "source_type": "standard",
           "quote": "Server Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing."}]

d = {"items": [{
    "item_key": "ad_delegation.chain.host", "class_id": "ad_delegation", "kind": "chain_link",
    "claim": "A claim with two independent publishers.",
    "body": "fixture body", "surface": "web", "severity_hint": "high",
    "hunting_value": "t", "disproof": "d", "sources": SRCS_A,
    "chain": {"chain_key": "dbg-chain-x", "name": "dbg chain", "goal": "domain_admin",
              "steps": [{"ord": 1, "action": "enumerate", "why": "because"},
                        {"ord": 2, "action": "forge", "why": "because"}]},
}]}

con = store.open_db(create=True)
con.execute("INSERT OR IGNORE INTO bug_class (id,name,status) VALUES (?,?,?)",
            ("ad_delegation", "AD Delegation", "researching"))
con.commit()
con.close()

f = Path(SANDBOX) / "dbg.json"
f.write_text(json.dumps(d, indent=1), encoding="utf-8")

res = wks_ingest.ingest_file(f, verify=False, dry=True)
print("shape_errors:", json.dumps(res["shape_errors"], indent=1))
print("rejected_fabricated:", json.dumps(res["rejected_fabricated"], indent=1))
print("promoted:", json.dumps(res["promoted"], indent=1))
print("held:", json.dumps(res["held"], indent=1))
print("chain_errors:", json.dumps(res.get("chain_errors"), indent=1))
print("chains_written:", res.get("chains_written"))

con = store.open_db(create=False)
print("\nitems in db:", con.execute("SELECT COUNT(*) FROM item").fetchone()[0])
print("chains in db:", con.execute("SELECT COUNT(*) FROM chain").fetchone()[0])
con.close()