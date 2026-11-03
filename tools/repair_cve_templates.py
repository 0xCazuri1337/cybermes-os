#!/usr/bin/env python3
"""Rewrite the generated CVE-template rows from their cited records.

The `*.technique.*_cve_*` rows in `exposed_services` and `linux_privesc` were
generated from one sentence shape: "X documents CVE-... as a route from an
authenticated user to elevated privileges."  That sentence is not evidence for
the CVE's impact, and the gate correctly holds it as `TEMPLATE_CLAIM`.

This tool repairs a reviewed manifest by replacing the claim, body, disproof,
class, and source quotes from the NVD record and the matching CWE definition.
It does not guess: every quote is fetched live and checked with
`wks.verify_quotes.find_quote` before the row is touched.  The old citation
links are removed because the rewritten claim is supported by the two records
in the manifest, not by the old write-up page.

    python3 tools/repair_cve_templates.py --manifest knowledge/incoming/pending/...
    python3 tools/repair_cve_templates.py --manifest ... --apply

The default is a dry run.  `--apply` rewrites rows in place and re-runs the
real gate; the JSON report records every accepted, held, or failed rewrite.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import pipeline, quality, store, verify_quotes  # noqa: E402

DEFAULT_OUT = ROOT / "learning" / "gaps" / "cve-template-repairs.json"


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="repair_cve_templates.py")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--apply", action="store_true",
                    help="write the reviewed rewrites (default: verify only)")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)

    manifest = Path(args.manifest)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    items = data["items"] if isinstance(data, dict) else data
    con = store.open_db()
    results = []

    for spec in items:
        old_key = spec.get("old_item_key") or spec.get("item_key")
        new_key = spec.get("new_item_key") or old_key
        result = {"old_item_key": old_key, "new_item_key": new_key,
                  "class_id": spec.get("class_id"), "status": "planned"}
        row = store.get_item(con, old_key)
        if row is None:
            result["status"] = "missing"
            results.append(result)
            continue
        if new_key != old_key and store.get_item(con, new_key) is not None:
            result["status"] = "collision"
            results.append(result)
            continue

        fetched = []
        source_errors = []
        for source in spec.get("sources") or []:
            url = source.get("url")
            quote = source.get("quote")
            if not url or not quote:
                source_errors.append({"url": url, "error": "missing url/quote"})
                continue
            got = pipeline.fetch(url, limit=900_000, resolve_moved=False)
            if got.get("access_state") != "ACTIVE":
                source_errors.append({"url": url,
                                      "error": f"access_state={got.get('access_state')}"})
                continue
            if not verify_quotes.find_quote(got.get("text") or "", quote):
                source_errors.append({"url": url, "error": "quote_not_found"})
                continue
            fetched.append({
                "url": url,
                "source_type": source.get("source_type", "writeup"),
                "quote": quote,
                "http_status": got.get("http_status"),
                "content_hash": got.get("content_hash"),
            })
        if source_errors:
            result["status"] = "quote_failed"
            result["source_errors"] = source_errors
            results.append(result)
            continue
        if len(fetched) < 2:
            result["status"] = "insufficient_verified_sources"
            results.append(result)
            continue

        result["sources"] = [{"url": s["url"], "source_type": s["source_type"]}
                             for s in fetched]
        if not args.apply:
            results.append(result)
            continue

        now = store.now()
        con.execute(
            """UPDATE item SET item_key=?, class_id=?, claim=?, kind=?, body=?,
                               disproof=?, status='active', updated_at=?
               WHERE id=?""",
            (new_key, spec["class_id"], spec["claim"], spec.get("kind", "technique"),
             spec.get("body"), spec.get("disproof"), now, int(row["id"])),
        )
        con.execute("DELETE FROM item_source WHERE item_id=?", (int(row["id"]),))
        for source in fetched:
            sid = store.upsert_source(
                con, source["url"], host_of(source["url"]),
                source_type=source["source_type"],
                publisher=host_of(source["url"]),
                http_status=source.get("http_status"),
                content_hash=source.get("content_hash"),
            )
            store.link_source(con, int(row["id"]), sid,
                              quote=source["quote"])
        con.commit()
        verdict = quality.assess(con, int(row["id"]))
        store.set_state(con, int(row["id"]), verdict["state"],
                        verdict["score"], verdict["reasons"])
        con.commit()
        result["status"] = "applied"
        result["validation_state"] = verdict["state"]
        result["score"] = round(verdict["score"], 3)
        result["tags"] = verdict.get("tags", [])
        results.append(result)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest": str(manifest),
        "applied": bool(args.apply),
        "summary": {
            "rows": len(results),
            "statuses": {s: sum(1 for r in results if r["status"] == s)
                         for s in sorted({r["status"] for r in results})},
        },
        "rows": results,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"wrote {out}")
    print("statuses:", report["summary"]["statuses"])
    for r in results:
        detail = r.get("error") or r.get("source_errors") or ""
        print(f"  {r['status']:10} {r['old_item_key']} -> {r['new_item_key']}"
              + (f" {detail}" if detail else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
