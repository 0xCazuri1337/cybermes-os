"""Register bugbountydaily.com as a LEAD-DISCOVERY source, not evidence.

Why it cannot be an evidence publisher
--------------------------------------
The RSS feed returns a bare list of LINKS with no article text:
  https://pyqacwkytiyzciltgsal.supabase.co/.../feeds/rss.xml  -> 200, 6193 chars
  of `https://host/path` + a numeric id + a date. There is no prose, so there is
  no contiguous span to quote. An item citing it would carry a quote that does
  not exist on the page — exactly the fabrication the gate exists to refuse.

So it is registered with source_type='index', which routes it to DISCOVERY:
`researcher` follows the links to the real publishers (varonis.com,
jorianwoltjer.com, lab.ctbb.show, ...) and the ARTICLE is the citable source.
That is the same trust rule already applied to `social` sources.

All hosts reachable from this host were probed before writing this:
  varonis.com, bobdahacker.com, blog.ammaraskar.com, brutecat.com,
  blog.silentsignal.eu, elttam.com, jorianwoltjer.com, sectricity.com,
  lab.ctbb.show, flatt.tech  -> all HTTP 200 via wks.pipeline.fetch
"""
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

import sqlite3  # noqa: E402

FEED = "https://pyqacwkytiyzciltgsal.supabase.co/storage/v1/object/public/feeds/rss.xml"
SITE = "https://bugbountydaily.com/"

con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
con.row_factory = sqlite3.Row
now = "2026-10-04T13:20:00+00:00"

for url, host, title, stype, notes in (
    (FEED, "pyqacwkytiyzciltgsal.supabase.co",
     "BugBountyDaily RSS — daily public bug-bounty writeup index",
     "index",
     "DISCOVERY ONLY. Body is a bare list of links; no quotable prose. "
     "Never promote an item on this host alone — follow the link and cite "
     "the publisher's own article."),
    (SITE, "bugbountydaily.com",
     "BugBountyDaily — public bug-bounty writeup aggregator",
     "index",
     "DISCOVERY ONLY. Aggregator front end for the RSS above."),
):
    con.execute(
        "INSERT INTO source (url, host, title, publisher, source_type, authority,"
        " retrieved_at, notes, access_state, access_checked_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(url) DO UPDATE SET title=excluded.title,"
        " source_type=excluded.source_type, notes=excluded.notes,"
        " access_state=excluded.access_state,"
        " access_checked_at=excluded.access_checked_at",
        (url, host, title, host, stype, 3, now, notes, "ACTIVE", now))
    con.commit()
    row = con.execute("SELECT url, host, source_type, access_state FROM source"
                      " WHERE url=?", (url,)).fetchone()
    print(f"  {row['source_type']:6} {row['access_state']:7} {row['host']}")

print("\nindex-type sources registered:")
for r in con.execute("SELECT host, count(*) n FROM source WHERE source_type='index'"
                     " GROUP BY host"):
    print(f"  {r['host']} ({r['n']})")
con.close()