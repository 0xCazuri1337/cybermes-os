"""FORCE-verify every registered source. Measured, never declared.

The audit's standing complaint was that the corpus could not tell a page that
was fetched from one that was merely declared -- and this module exists to end
that ambiguity for the SOURCE REGISTRY itself. `research_sources.py` declares an
`access` tier per entry; `db/sources.json` declares another. Both are CLAIMS.

This fetches every one of them, live, and reports the difference:

    DECLARED open    MEASURED ACTIVE            confirmed
    DECLARED open    MEASURED BROWSER_REQUIRED  a 200 that returned no prose
    DECLARED open    MEASURED BLOCKED           refused to this client
    DECLARED walled  MEASURED ACTIVE            the wall is down / never existed
    DECLARED json    MEASURED ACTIVE            machine endpoint answered
    DECLARED key     MEASURED BLOCKED           no key configured (expected)

Every measurement is persisted through `store.record_access`, so the store
carries the measured state and `access_detail` records the disagreement. A
declared tier that no longer matches reality becomes visible data instead of a
comment in a source file.

Resumable: results are appended to a JSONL as they land, so a long run can be
interrupted and continued, and a partial run is still useful evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wks import config, pipeline, store, transport

RESULTS = Path(config.ROOT) / "state" / "source-verification.jsonl"

# Declared access tier -> the measured states that CONFIRM it. Anything else is
# a disagreement worth printing.
CONFIRMS: dict[str, tuple[str, ...]] = {
    "open": ("ACTIVE",),
    "json": ("ACTIVE",),
    "key": ("ACTIVE", "BLOCKED"),      # no key configured is expected, not a fault
    "js": ("BROWSER_REQUIRED", "ACTIVE"),
    "walled": ("BLOCKED", "BROWSER_REQUIRED", "RATE_LIMITED", "ACTIVE"),
}


def _load_sourcesjson() -> list[dict[str, Any]]:
    p = config.ROOT / "db" / "sources.json"
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8")).get("sources", [])


def inventory() -> list[dict[str, Any]]:
    """Every source worth forcing, tagged with what it DECLARES."""
    from wks import research_sources as RS

    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for s in RS.RESEARCH_SOURCES:
        if s.url in seen:
            continue
        seen.add(s.url)
        out.append({"url": s.url, "declared": s.access, "tier": s.tier,
                    "declared_by": "research_sources.RESEARCH_SOURCES",
                    "title": s.title, "role": "lead"})

    for e in _load_sourcesjson():
        url = e.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "declared": e.get("access"),
                    "tier": e.get("tier"),
                    "declared_by": "db/sources.json",
                    "title": e.get("title"), "role": e.get("role")})
    return out


def verdict(declared: str | None, measured: str) -> str:
    ok = CONFIRMS.get(declared or "", None)
    if ok is None:
        return "UNDECLARED"
    return "confirmed" if measured in ok else "DISAGREES"


def verify_one(url: str) -> dict[str, Any]:
    """One forced measurement. The registry's declared tier is irrelevant here
    -- this asks the network, not the source file."""
    t0 = time.monotonic()
    got = pipeline.fetch(url, limit=1_500_000)
    return {
        "url": url,
        "measured_state": got.get("access_state"),
        "http_status": got.get("status"),
        "content_hash": got.get("content_hash"),
        "text_chars": len(got.get("text", "") or ""),
        "mirror": got.get("mirror"),
        "moved_from": got.get("moved_from"),
        "access_detail": (got.get("error") or
                          (f"shell-only response, {len(got.get('text') or '')} chars"
                           if got.get("access_state") == "BROWSER_REQUIRED"
                           else None)),
        "attempts": got.get("attempts"),
        "waited_seconds": got.get("waited_seconds"),
        "seconds": round(time.monotonic() - t0, 2),
    }


def run(apply: bool = False, only: str | None = None, limit: int = 0) -> dict[str, Any]:
    items = inventory()
    if only:
        items = [i for i in items if only in i["url"]]
    if limit:
        items = items[:limit]

    done: dict[str, dict[str, Any]] = {}
    if RESULTS.exists():
        for line in RESULTS.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                done[r["url"]] = r
            except ValueError:
                continue

    con = store.open_db(create=apply) if apply else None
    rows: list[dict[str, Any]] = []
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a", encoding="utf-8") as sink:
        for n, item in enumerate(items, 1):
            prior = done.get(item["url"])
            if prior:
                r = prior
            else:
                r = verify_one(item["url"])
                r["declared"] = item["declared"]
                r["declared_by"] = item["declared_by"]
                r["role"] = item["role"]
                r["at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                sink.write(json.dumps(r, default=str) + "\n")
                sink.flush()
            r["verdict"] = verdict(item["declared"], r["measured_state"])
            rows.append({**item, **r})
            if apply and con is not None:
                # Persist the MEASURED state. record_access is an upsert, so a
                # registry entry the ingest has never seen still gets a row --
                # which is how a walled source becomes a recorded fact instead of
                # a comment in a source file.
                detail = f"{r['verdict']}: declared={item['declared']}"
                if r.get("access_detail"):
                    detail += f"; {r['access_detail']}"
                store.record_access(
                    con, r["url"], access_state=r["measured_state"],
                    http_status=r["http_status"],
                    content_hash=r["content_hash"],
                    detail=detail)
            if n % 10 == 0 or n == len(items):
                print(f"  verified {n}/{len(items)}", flush=True)

    if con is not None:
        con.commit()
        con.close()

    tally: dict[str, int] = {}
    vtally: dict[str, int] = {}
    for r in rows:
        tally[r["measured_state"]] = tally.get(r["measured_state"], 0) + 1
        vtally[r["verdict"]] = vtally.get(r["verdict"], 0) + 1
    return {
        "checked": len(rows),
        "measured_states": dict(sorted(tally.items())),
        "conformance": dict(sorted(vtally.items())),
        "disagreements": [
            {"url": r["url"], "declared": r["declared"], "measured": r["measured_state"],
             "http_status": r["http_status"], "chars": r["text_chars"],
             "detail": r.get("access_detail")}
            for r in rows if r["verdict"] in ("DISAGREES", "UNDECLARED")],
        "rate_limited_hosts": transport.rate_limited_hosts(),
        "results_file": str(RESULTS),
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.verify_sources")
    ap.add_argument("--apply", action="store_true",
                    help="persist measured states to the store")
    ap.add_argument("--only", help="substring filter on the url")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    out = run(apply=a.apply, only=a.only, limit=a.limit)
    rows = out.pop("rows")
    if a.json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    print(f"checked            : {out['checked']}")
    print(f"measured states    : {out['measured_states']}")
    print(f"declared vs measured: {out['conformance']}")
    if out["rate_limited_hosts"]:
        print(f"rate-limited hosts : {list(out['rate_limited_hosts'])}")
    print(f"\nDISAGREEMENTS ({len(out['disagreements'])}):")
    for d in out["disagreements"]:
        print(f"  declared={str(d['declared']):7} measured={str(d['measured']):18} "
              f"http={d['http_status']} chars={d['chars']}")
        print(f"      {d['url'][:96]}")
        if d.get("detail"):
            print(f"      {str(d['detail'])[:96]}")
    print(f"\nfull results: {out['results_file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())