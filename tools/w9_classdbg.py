"""Why is the class not visible? Check the actual INSERT result and what
open_db(create=True) does to the row.
"""
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="wks_clsdbg_")
os.environ["WKS_ROOT"] = SANDBOX
ROOT = Path(r"C:/Users/Administrator/.hermes/cyber")
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402

print("WKS_ROOT =", config.root())
print("db_path  =", config.db_path())

con = store.open_db(create=True)
print("\nSCHEMA bug_class DDL:")
ddl = con.execute("SELECT sql FROM sqlite_master WHERE name='bug_class'").fetchone()[0]
print(ddl)

cur = con.execute("INSERT OR IGNORE INTO bug_class (id,name,status) VALUES (?,?,?)",
                  ("ad_delegation", "AD Delegation", "researching"))
print("\ninsert rowcount:", cur.rowcount, "lastrowid:", cur.lastrowid)
con.commit()
print("rows now:", con.execute("SELECT COUNT(*) FROM bug_class").fetchone()[0])
print("all ids:", [r[0] for r in con.execute("SELECT id FROM bug_class").fetchall()][:20])
print("get_class('ad_delegation'):", store.get_class(con, "ad_delegation") is not None)
con.close()

# now reopen the way ingest does and see if the row survived
con2 = store.open_db(create=True)
print("\nafter reopen, rows:", con2.execute("SELECT COUNT(*) FROM bug_class").fetchone()[0])
print("after reopen, get_class:", store.get_class(con2, "ad_delegation") is not None)
con2.close()