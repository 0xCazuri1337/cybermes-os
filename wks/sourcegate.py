"""Wire the MEASURED source state into the learning loop.

The gap this closes, measured: `sourcebook.brief()` hands a research child a
list of URLs and an `access` tier read from `db/sources.json` -- a DECLARATION
written by a builder. Nothing in the loop consulted what was actually measured,
so a child could be sent to `hackerone.com/hacktivity` (declared `walled`, and
measured BLOCKED), spend its fetch budget discovering that, and return with
nothing. A walled host is not a lead; it is a dead end with a fetch budget.

Three changes, all read-through and all optional (the loop still works with no
verification on record):

  * `measured_state(con, url)` -- one row from the store, the MEASURED value.
  * `worklist()` marks each source `fetchable` / `walled` / `unmeasured` and
    puts the unusable ones in a `do_not_use` list.
  * `brief()` prints that list FIRST, so the child's first instruction is
    "these will not work, do not spend a cycle proving it".

Nothing here decides anything. `quality.py` remains the only writer of
`validation_state`, and an unmeasured source is reported as unmeasured rather
than assumed good -- the same rule the whole remediation follows.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from . import config

# Measured states a research child can actually quote from.
USABLE = ("ACTIVE",)

# States that will never yield a quote without human help. Naming them in the
# brief is the entire point: it converts a wasted fetch into a saved one.
UNUSABLE = ("BLOCKED", "PAYWALLED", "BROWSER_REQUIRED", "RATE_LIMITED", "STALE")


def measured_state(con: sqlite3.Connection | None, url: str) -> str | None:
    """The MEASURED state for a URL, or None when nothing has measured it.

    Read from `source.access_state`, which only `wks.verify_sources --apply`,
    `wks.verify_quotes --record` and `wks.staleness --apply` write. A row
    created by ingest alone carries UNVERIFIED, which is exactly the honest
    "declared, not measured" answer.
    """
    if con is None:
        return None
    try:
        row = con.execute(
            "SELECT access_state FROM source WHERE url=?", (url,)).fetchone()
    except sqlite3.Error:
        return None
    return row["access_state"] if row else None


def annotate(con: sqlite3.Connection | None,
             entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Split a source list by what is actually fetchable."""
    usable, unusable, unknown = [], [], []
    for e in entries:
        state = measured_state(con, e.get("url", ""))
        e = {**e, "measured_state": state}
        if state in USABLE:
            usable.append(e)
        elif state in UNUSABLE:
            unusable.append(e)
        else:
            unknown.append(e)
    return {"usable": usable, "unusable": unusable, "unmeasured": unknown}


def verification_summary(con: sqlite3.Connection | None) -> dict[str, Any]:
    """One line an operator can read to know how much of the registry is real."""
    if con is None:
        return {"verified": 0, "note": "no store connection"}
    rows = con.execute(
        "SELECT access_state, count(*) n FROM source GROUP BY 1").fetchall()
    census = {r["access_state"]: r["n"] for r in rows}
    total = sum(census.values())
    active = census.get("ACTIVE", 0)
    return {
        "sources": total,
        "active": active,
        "unverified": census.get("UNVERIFIED", 0),
        "blocked_or_worse": total - active - census.get("UNVERIFIED", 0),
        "coverage_pct": round(100.0 * active / total, 1) if total else 0.0,
    }