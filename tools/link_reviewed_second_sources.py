#!/usr/bin/env python
"""Link a reviewed second-publisher quote into an existing item.

This is deliberately narrow. It is NOT an automatic corroborator: every quote
in the manifest must already have been read and judged against the claim. The
tool's job is to make the mechanical steps impossible to skip:

  1. fetch the cited page LIVE;
  2. require the exact span to pass `wks.verify_quotes.find_quote`;
  3. count publisher ORGS, not hostnames;
  4. leave claim/body/disproof untouched unless the manifest explicitly
     supplies a replacement (only used where the old wording was unsupported);
  5. re-run the same gate the corpus uses, from the database, after writing.

    python3 tools/link_reviewed_second_sources.py \
        --manifest research/pending/second-source-batch-20261028.json
    python3 tools/link_reviewed_second_sources.py ... --apply

Without `--apply` it performs every fetch and quote check and writes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import config, pipeline, quality, store  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _org(url: str) -> str:
    return config.publisher_org(pipeline.host_of(url))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="link_reviewed_second_sources.py")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    entries = manifest.get("items") or []
    con = store.open_db(create=False)
    problems: list[str] = []
    checks: list[dict] = []

    for entry in entries:
        key = entry["item_key"]
        item = store.get_item(con, key)
        if item is None or item["status"] != "active":
            problems.append(f"{key}: not an active item")
            continue
        existing = store.item_evidence(con, item["id"])
        old_orgs = {_org(e["url"]) for e in existing if e["url"]}
        old_hosts = {e["host"] for e in existing}
        new_sources = []
        for src in entry.get("sources") or []:
            url = src["url"]
            got = pipeline.fetch(url, limit=2_000_000, resolve_moved=False)
            state = got.get("access_state")
            if state != "ACTIVE":
                problems.append(f"{key}: {url} -> {state}")
                continue
            text = got.get("text") or ""
            quote = src["quote"]
            if not find_quote(text, quote):
                problems.append(f"{key}: quote NOT FOUND on {url}: {quote[:100]!r}")
                continue
            org = _org(url)
            new_sources.append({**src, "org": org, "fetch": got})
        if not new_sources:
            continue
        after_orgs = old_orgs | {s["org"] for s in new_sources}
        unlink_hosts = set(entry.get("unlink_hosts") or [])
        if unlink_hosts:
            after_orgs = {_org(e["url"]) for e in existing
                          if e["url"] and e["host"] not in unlink_hosts}
            after_orgs |= {s["org"] for s in new_sources}
        checks.append({
            "item_key": key,
            "item_id": item["id"],
            "old_state": con.execute(
                "select validation_state from quality where item_id=?",
                (item["id"],)).fetchone()["validation_state"],
            "old_orgs": sorted(old_orgs),
            "new_orgs": sorted(after_orgs),
            "old_hosts": sorted(old_hosts),
            "unlink_hosts": sorted(unlink_hosts),
            "claim_changed": bool(entry.get("claim")),
            "body_changed": bool(entry.get("body")),
            "sources": [{k: s[k] for k in ("url", "org", "source_type", "quote")}
                        for s in new_sources],
            "entry": entry,
            "fetched": {s["url"]: s["fetch"] for s in new_sources},
        })
        if len(after_orgs) < config.MIN_PUBLISHER_HOSTS:
            problems.append(f"{key}: after link only orgs {sorted(after_orgs)}")

    if problems:
        print("PREFLIGHT FAILED -- nothing written")
        for p in problems:
            print("  -", p)
        return 1

    print(f"preflight OK: {len(checks)} item(s), "
          f"{sum(len(c['sources']) for c in checks)} quote(s)")
    for c in checks:
        print(f"  {c['item_key'][:72]:72} orgs {c['old_orgs']} -> {c['new_orgs']}")
        for s in c["sources"]:
            print(f"      + {s['org']:22} {s['quote'][:96]!r}")

    if not args.apply:
        print("dry run; re-run with --apply to write")
        return 0

    now = store.now()
    report = {"generated_at": _now(), "applied": True, "rows": []}
    with con:
        for c in checks:
            item = con.execute("select * from item where id=?", (c["item_id"],)).fetchone()
            entry = c["entry"]
            updates = {"updated_at": now}
            if entry.get("claim"):
                updates["claim"] = entry["claim"]
            if entry.get("body"):
                updates["body"] = entry["body"]
            sets = ", ".join(f"{k}=?" for k in updates)
            con.execute(f"update item set {sets} where id=?",
                        (*updates.values(), item["id"]))
            for s in c["sources"]:
                got = c["fetched"][s["url"]]
                sid = store.upsert_source(
                    con, s["url"], pipeline.host_of(s["url"]),
                    source_type=s["source_type"],
                    http_status=got.get("http_status"),
                    content_hash=got.get("content_hash"),
                    access_state=got.get("access_state"),
                    access_checked_at=now,
                    notes="reviewed second-publisher quote, 2026-10-28",
                )
                store.link_source(
                    con, item["id"], sid, quote=s["quote"],
                    locator="reviewed live 2026-10-28 by link_reviewed_second_sources",
                )
            for ev in store.item_evidence(con, item["id"]):
                if ev["host"] in set(entry.get("unlink_hosts") or []):
                    store.unlink_source(con, item["id"], ev["id"])
            result = quality.assess(con, item["id"])
            store.set_state(con, item["id"], result["state"],
                            result["score"], result["reasons"])
            report["rows"].append({
                "item_key": c["item_key"],
                "before": c["old_state"],
                "after": result["state"],
                "score": result["score"],
                "reasons": result["reasons"],
                "orgs": c["new_orgs"],
            })
            print(f"  {c['item_key'][:72]:72} {c['old_state']} -> "
                  f"{result['state']} ({result['score']:.3f}) {result['reasons']}")

    out = ROOT / "learning" / "gaps" / "second-source-apply-20261028.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
