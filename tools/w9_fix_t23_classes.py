"""Fix the T23 fixture class registration.

MEASURED: `bug_class.surface` and `first_seen` are NOT NULL, so
`INSERT OR IGNORE INTO bug_class (id,name,status)` silently inserted NOTHING
(rowcount 0) and the fixture class never existed. Every item then failed shape
validation with `unknown class`, so the chain logic never ran and T23 reported
5 failures that had nothing to do with chains.

Rule worth keeping: an INSERT that silently affects 0 rows looks exactly like a
successful one unless you check `rowcount`. Use `store.add_class` if it exists,
otherwise supply every NOT NULL column and assert the row landed.
"""
import io
import re

P = r"C:/Users/Administrator/.hermes/cyber/eval/test_wks_chains.py"
src = io.open(P, encoding="utf-8").read()

OLD = '''con.execute("INSERT OR IGNORE INTO bug_class (id,name,status) VALUES (?,?,?)",
            ("ad_delegation", "AD Delegation", "researching"))
con.execute("INSERT OR IGNORE INTO bug_class (id,name,status) VALUES (?,?,?)",
            ("ad_kerberos", "AD Kerberos", "researching"))
con.execute("INSERT OR IGNORE INTO bug_class (id,name,status) VALUES (?,?,?)",
            ("ad_acl_abuse", "AD ACL Abuse", "researching"))
con.commit()'''

NEW = '''# `surface` and `first_seen` are NOT NULL: an INSERT that omits them is
# silently IGNOREd (rowcount 0) and the class never exists, which surfaces as a
# baffling "unknown class" for every item. Assert the row landed.
from datetime import datetime, timezone  # noqa: E402
_now = datetime.now(timezone.utc).isoformat(timespec="seconds")
for _cid, _name, _surface in (("ad_delegation", "AD Delegation", "identity"),
                              ("ad_kerberos", "AD Kerberos", "identity"),
                              ("ad_acl_abuse", "AD ACL Abuse", "identity")):
    _c = con.execute("INSERT OR IGNORE INTO bug_class "
                     "(id,name,surface,status,first_seen) VALUES (?,?,?,?,?)",
                     (_cid, _name, _surface, "researching", _now))
    if con.execute("SELECT COUNT(*) FROM bug_class WHERE id=?",
                   (_cid,)).fetchone()[0] != 1:
        raise SystemExit("fixture class %s did not register" % _cid)
con.commit()'''

if OLD not in src:
    raise SystemExit("class-registration block not found - refusing to guess")
src = src.replace(OLD, NEW, 1)
io.open(P, "w", encoding="utf-8").write(src)
print("fixed class registration in", P)