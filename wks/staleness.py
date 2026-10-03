"""Stale-source detection by content hash.

The audit's verdict was blunt: `metrics.stale_rate_pct: 0.0` was reporting
"not measured" as "nothing is stale". Nothing could measure it, because
`source.content_hash` was NULL on every row -- there was no baseline to compare
a later fetch against.

With `wks.http` recording `content_hash` and `access_state` on every fetch, the
comparison becomes possible, and this module performs it:

    STALE  a source that was ACTIVE and now is not, or whose prose hash changed
    CHANGED a source whose prose changed but is still reachable

Both are reported separately, because they mean different things. A page
rewritten in place is not dead; a page that stopped answering is. Collapsing
them into one "stale" bucket is how a documentation reorganisation gets read as
knowledge loss.

Report-only by default. `--apply` writes `access_state='STALE'`, and that write
is monotonic: it never clears a source that a later fetch proved ACTIVE again.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from typing import Any

from wks import config, store, transport as http

# A source is only a staleness CANDIDATE if something measured it before. A row
# that has never been fetched cannot be stale -- it is unmeasured, and calling
# it stale would be inventing a finding.
CANDIDATE_WHERE = (
    "access_state='ACTIVE' AND content_hash IS NOT NULL AND content_hash<>''")


def candidates(con: sqlite3.Connection, limit: int = 0) -> list[sqlite3.Row]:
    sql = f"SELECT id, url, host, access_state, content_hash, last_ok_at FROM source WHERE {CANDIDATE_WHERE} ORDER BY host, url"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return con.execute(sql).fetchall()


def unmeasured(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """Sources with no measured baseline. Reported, never counted as stale."""
    return con.execute(
        "SELECT id, url, host, access_state FROM source "
        "WHERE access_state<>'ACTIVE' AND (content_hash IS NULL OR content_hash='') "
        "ORDER BY host, url").fetchall()


def check_one(url: str, known_hash: str | None) -> dict[str, Any]:
    """Re-fetch one URL and compare its prose hash against the recorded one."""
    from wks import pipeline
    got = pipeline.fetch(url)
    new_hash = got.get("content_hash")
    state = got.get("access_state", "UNVERIFIED")
    if state != "ACTIVE":
        return {"url": url, "verdict": "STALE", "reason": f"was ACTIVE, now {state}",
                "access_state": state, "http_status": got.get("status"),
                "known_hash": known_hash, "new_hash": new_hash,
                "detail": got.get("error")}
    if known_hash and new_hash and new_hash != known_hash:
        return {"url": url, "verdict": "CHANGED", "reason": "prose hash differs",
                "access_state": state, "http_status": got.get("status"),
                "known_hash": known_hash, "new_hash": new_hash, "detail": None}
    return {"url": url, "verdict": "OK", "reason": "reachable, prose unchanged",
            "access_state": state, "http_status": got.get("status"),
            "known_hash": known_hash, "new_hash": new_hash, "detail": None}


def sweep(con: sqlite3.Connection, *, limit: int = 0,
          apply: bool = False) -> dict[str, Any]:
    """Re-fetch every measured source and report what moved.

    Read-only unless `apply`. `apply` writes STALE / the new hash; it is
    monotonic, so a source that a later fetch proves ACTIVE again is recorded
    ACTIVE rather than being pinned to STALE forever.
    """
    rows = candidates(con, limit)
    results = [check_one(r["url"], r["content_hash"]) for r in rows]
    tally: dict[str, int] = {}
    for r in results:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1

    applied = []
    if apply:
        for r in results:
            if r["verdict"] == "OK":
                continue
            moved = store.record_access(
                con, r["url"],
                access_state=("STALE" if r["verdict"] == "STALE" else "ACTIVE"),
                http_status=r.get("http_status"),
                content_hash=r.get("new_hash"),
                detail=f"staleness sweep: {r['verdict']} ({r['reason']})")
            if moved:
                applied.append({"url": r["url"], "verdict": r["verdict"]})
        con.commit()

    unm = unmeasured(con)
    return {
        "checked": len(results),
        "candidates": len(rows),
        "tally": tally,
        "results": results,
        "applied": applied,
        "unmeasured": len(unm),
        "unmeasured_note": (
            "sources with no measured baseline cannot be judged stale; they are "
            "UNVERIFIED, and counting them as stale would invent a finding"),
        "unmeasured_urls": [r["url"] for r in unm[:50]],
        "rate_limited_hosts": http.rate_limited_hosts(),
        "store": str(config.DB_PATH),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="wks.staleness")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--apply", action="store_true", help="write STALE + new hashes")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    con = store.open_db(create=False)
    out = sweep(con, limit=a.limit, apply=a.apply)
    con.close()
    if a.json:
        print(json.dumps(out, indent=1, default=str))
    else:
        print(f"checked {out['checked']} measured sources: "
              + "  ".join(f"{k}={v}" for k, v in sorted(out["tally"].items())))
        print(f"unmeasured (cannot be judged): {out['unmeasured']}")
        for r in out["results"]:
            if r["verdict"] != "OK":
                print(f"  [{r['verdict']:7}] {r['url'][:100]}  {r['reason']}")
        if out["rate_limited_hosts"]:
            print("  rate-limited hosts: "
                  f"{list(out['rate_limited_hosts'])} -- these are NOT stale")
        if a.apply:
            print(f"applied: {len(out['applied'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())