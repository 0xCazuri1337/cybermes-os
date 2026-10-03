
import sqlite3, sys
sys.path.insert(0, ".")
from wks.config import publisher_org
c = sqlite3.connect("file:db/wks.db?mode=ro", uri=True)
for k in ["race", "graphql", "cmd", "ldap", "api_trust", "xxe"]:
    orgs = {publisher_org(r[0]) for r in c.execute(
        "select s.host from item i join item_source x on x.item_id=i.id "
        "join source s on s.id=x.source_id where i.class_id=?", (k,))}
    print(f"{k:12s} orgs={len(orgs)}")
