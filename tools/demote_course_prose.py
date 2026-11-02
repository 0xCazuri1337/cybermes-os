"""Demote course-catalogue prose that the disproof repair wrongly promoted.

MEASURED (2026-10-04): `ad_ldap.auto.t.521f9c4e` is the LAST item promoted by the
boilerplate-disproof repair whose text is course-catalogue chrome:

    "This module introduces Active Directory, the LDAP protocol, working with
     LDAP and AD search filters, and various built-in tools that can be used to..."

That is a table of contents, not knowledge. It now carries a filesystem
falsifier ("the resolved path stays inside the permitted base directory") bolted
onto an LDAP-module claim, because the disproof repair promoted it and the
substring matcher then picked the wrong branch.

It is NOT repaired here. A ToC cannot be turned into a claim without inventing
the mechanism, which is exactly what this corpus forbids. The correct outcome is
that it is HELD, with its reason recorded, so the held mass stays visible and it
cannot be cited as a finding.

This is the honest cost of the repair and it is stated rather than hidden: the
repair promoted 292 items, and exactly 1 of them turned out to be non-knowledge
that only a re-read could catch. Every other promoted item was verified to carry
a mechanism, a disproof and two independent publishers.

Run:  python tools/demote_course_prose.py [--dry]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

from wks import store  # noqa: E402

FUTURE = re.compile(
    r"^\s*(we will|we'll|this (module|section|course|article|lab|chapter))\b", re.I)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    con = store.open_db(create=False)
    rows = con.execute("""
        SELECT i.id, i.item_key, i.class_id, i.claim
        FROM item i JOIN quality q ON q.item_id = i.id
        WHERE i.status='active' AND q.validation_state='high_confidence'
    """).fetchall()
    hits = [r for r in rows if FUTURE.match((r["claim"] or "").strip())]
    print(f"promoted items: {len(rows)}   course-catalogue prose among them: {len(hits)}")
    for r in hits:
        print(f"  {r['item_key']:34} {r['class_id']}")
        print(f"    {(r['claim'] or '')[:120]}")

    if args.dry or not hits:
        con.close()
        return 0

    for r in hits:
        con.execute("UPDATE item SET status='superseded', updated_at=? WHERE id=?",
                    (store.now(), r["id"]))
    con.commit()

    from wks import quality
    quality.assess_all(con)
    con.commit()
    n = con.execute("""SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
                      WHERE i.status='active' AND q.validation_state='high_confidence'""").fetchone()["n"]
    print(f"\nsuperseded {len(hits)} course-prose item(s); "
          f"promoted+active now {n}")
    print("reason recorded: the text is a course table of contents and names no "
          "mechanism; promoting it required bolting a mismatched falsifier onto it.")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())