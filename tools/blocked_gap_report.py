#!/usr/bin/env python
"""Write the single-publisher gap worklist for the learning loop.

The gate holds an item as INSUFFICIENT_PUBLISHER_HOSTS when its citations all
resolve to one publisher org. `db/sources.json` already knows which normative
sources belong to each class, so the blocks are usually closable: the item just
needs a verified citation from a different org.

This tool does NOT fetch pages, select quotes, or write to the corpus. It only
joins the gate's held items to the sourcebook's normative candidates and writes
a reviewable worklist under `knowledge/activity/gaps/`. A candidate URL is a place to
read, never evidence by itself.

    python tools/blocked_gap_report.py

Writes:
    knowledge/activity/gaps/single-publisher-<YYYYMMDD>.md
    knowledge/activity/gaps/single-publisher-<YYYYMMDD>.json
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GAPS = ROOT / "learning" / "gaps"

# A single-publisher hold can be accompanied by other gate findings. The
# worklist must not imply that adding a citation closes an item whose claim or
# disproof is also broken. These sets are deliberately explicit so a new gate
# tag shows up as an unknown blocker instead of being silently called
# "publisher-only".
_SOURCE_TAGS = {
    "NO_SOURCES", "INSUFFICIENT_SOURCES", "INSUFFICIENT_PUBLISHER_HOSTS",
    "BUILDER_PAGE_NOT_PUBLISHER", "DISCOVERY_ONLY_SOURCE",
}
_QUOTE_TAGS = {"LABEL_ONLY_QUOTE"}
_CLAIM_TAGS = {
    "OFF_CLASS_TOPIC", "MODULE_FILLER", "TEMPLATE_CLAIM",
    "UNFALSIFIABLE_CLAIM", "VAGUE_CLAIM", "FABRICATED_REFS",
}
_DISPROOF_TAGS = {"BOILERPLATE_DISPROOF", "CIRCULAR_DISPROOF"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gate_tags(raw: str | None) -> set[str]:
    try:
        values = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return set()
    return {str(v).split("(", 1)[0].strip() for v in values}


def _blocker_class(raw: str | None) -> str:
    tags = _gate_tags(raw)
    claim = tags & _CLAIM_TAGS
    disproof = tags & _DISPROOF_TAGS
    quote = tags & _QUOTE_TAGS
    if claim and disproof:
        return "claim_and_disproof"
    if claim:
        return "claim_repair"
    if disproof:
        return "disproof_repair"
    if quote:
        return "quote_repair"
    return "publisher_only"


def _orgs(con: sqlite3.Connection, item_id: int
          ) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    from wks import config

    rows = con.execute(
        """SELECT DISTINCT s.host, s.url
           FROM item_source x JOIN source s ON s.id=x.source_id
           WHERE x.item_id=? ORDER BY s.host, s.url""", (item_id,)).fetchall()
    sources = [{"host": r["host"], "url": r["url"],
                "builder": config.is_builder_host(r["host"])} for r in rows]
    counted = [r for r in rows if not config.is_builder_host(r["host"])]
    orgs = sorted({config.publisher_org(r["host"]) for r in counted if r["host"]})
    builder_hosts = sorted({r["host"] for r in rows
                            if config.is_builder_host(r["host"])})
    return orgs, sources, builder_hosts


def _candidates(con: sqlite3.Connection, class_id: str,
                current_orgs: set[str]) -> list[dict[str, Any]]:
    """Normative sources from an org the item does not already cite.

    One URL per (org, measured_state) pair is enough for a worklist; listing
    every page in a publisher would turn the report into noise. Prefer a
    measured-ACTIVE page, then the first page in sourcebook order.
    """
    from wks import sourcebook

    try:
        work = sourcebook.worklist(class_id, con)
    except Exception as exc:  # missing/corrupt registry must be visible
        return [{"error": f"{type(exc).__name__}: {exc}"}]

    chosen: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in work.get("normative", []):
        org = entry.get("publisher_org")
        url = entry.get("url")
        if not org or not url or org in current_orgs:
            continue
        state = entry.get("measured_state") or "unmeasured"
        key = (org, state)
        rank = 0 if state == "ACTIVE" else 1
        old = chosen.get(key)
        if old is None or rank < old["_rank"]:
            chosen[key] = {
                "org": org,
                "url": url,
                "source_type": entry.get("source_type"),
                "measured_state": state,
                "_rank": rank,
            }
    out = sorted(chosen.values(), key=lambda e: (e["org"], e["_rank"], e["url"]))
    for e in out:
        e.pop("_rank", None)
    return out


def build(con: sqlite3.Connection) -> dict[str, Any]:
    rows = con.execute(
        """SELECT i.id, i.item_key, i.class_id, i.claim, i.kind, q.gate_reasons
           FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.status='active' AND q.validation_state='under_review'
             AND q.gate_reasons LIKE '%INSUFFICIENT_PUBLISHER_HOSTS%'
           ORDER BY i.class_id, i.item_key""").fetchall()

    classes: dict[str, dict[str, Any]] = {}
    for row in rows:
        current_orgs, sources, builder_hosts = _orgs(con, row["id"])
        cands = _candidates(con, row["class_id"], set(current_orgs))
        entry = classes.setdefault(row["class_id"], {
            "blocked": 0,
            "candidates": [],
            "items": [],
        })
        entry["blocked"] += 1
        # Accumulate class-level candidates once, keeping org/state/url unique.
        known = {(c.get("org"), c.get("measured_state"), c.get("url"))
                 for c in entry["candidates"]}
        for c in cands:
            key = (c.get("org"), c.get("measured_state"), c.get("url"))
            if key not in known:
                entry["candidates"].append(c)
                known.add(key)
        entry["items"].append({
            "item_key": row["item_key"],
            "claim": row["claim"],
            "kind": row["kind"],
            "gate_reasons": json.loads(row["gate_reasons"] or "[]"),
            "blocker_class": _blocker_class(row["gate_reasons"]),
            "current_orgs": current_orgs,
            "builder_hosts": builder_hosts,
            "current_sources": sources,
            "candidates": cands,
        })

    for entry in classes.values():
        entry["candidates"].sort(
            key=lambda c: (c.get("org") or "", c.get("measured_state") or ""))
        entry["items"].sort(key=lambda i: i["item_key"])

    total = sum(e["blocked"] for e in classes.values())
    closable = sum(1 for e in classes.values() for i in e["items"] if i["candidates"])
    blockers: dict[str, int] = {}
    for e in classes.values():
        for i in e["items"]:
            blockers[i["blocker_class"]] = blockers.get(i["blocker_class"], 0) + 1
    publisher_only_with_candidate = sum(
        1 for e in classes.values() for i in e["items"]
        if i["blocker_class"] == "publisher_only" and i["candidates"]
    )
    return {
        "generated_at": _now(),
        "db": "db/wks.db",
        "summary": {
            "blocked_items": total,
            "classes": len(classes),
            "items_with_candidate": closable,
            "items_without_candidate": total - closable,
            "publisher_only_with_candidate": publisher_only_with_candidate,
            "blocker_classes": dict(sorted(blockers.items())),
            "note": ("Candidates are normative sourcebook entries from a publisher "
                     "org the item does not already cite. They are reading targets, "
                     "not verified evidence; the normal quote-verification gate "
                     "still applies. Only publisher_only items can be closed by "
                     "adding a citation without also repairing the claim, quote, "
                     "or disproof."),
        },
        "classes": classes,
    }


def markdown(doc: dict[str, Any]) -> str:
    s = doc["summary"]
    L = [
        "# Single-publisher gap worklist",
        "",
        f"Generated: `{doc['generated_at']}` from `{doc['db']}`.",
        "",
        "The gate holds these items as `INSUFFICIENT_PUBLISHER_HOSTS`: after "
        "builder/static-hosting pages are excluded, every citation resolves to "
        "one publisher org. `db/sources.json` lists normative sources for the "
        "class; the candidates below are from a *different* org and are places "
        "to read, not evidence.",
        "",
        "**Never paste a quote into the corpus unless `wks.verify_quotes.find_quote` "
        "accepts it against the live page.** Candidate presence is not promotion.",
        "",
        "## Summary",
        "",
        f"- blocked items: **{s['blocked_items']}**",
        f"- classes: **{s['classes']}**",
        f"- items with at least one candidate: **{s['items_with_candidate']}**",
        f"- items without a candidate: **{s['items_without_candidate']}**",
        f"- publisher-only + candidate (citation may close it): "
        f"**{s['publisher_only_with_candidate']}**",
        f"- blocker classes: `{s['blocker_classes']}`",
        "",
        "Only `publisher_only` items are citation-closable. `claim_repair`, "
        "`quote_repair`, `disproof_repair`, and mixed items need the named "
        "repair first; adding a second publisher around a broken claim would "
        "launder it.",
        "",
        "## Classes",
        "",
        "| Class | Blocked | Candidate orgs |",
        "|---|---:|---|",
    ]
    for cid, e in sorted(doc["classes"].items(),
                         key=lambda kv: (-kv[1]["blocked"], kv[0])):
        orgs = sorted({c.get("org", "?") for c in e["candidates"]})
        L.append(f"| `{cid}` | {e['blocked']} | {', '.join(orgs) or '—'} |")
    L += ["", "## Detail", ""]
    for cid, e in sorted(doc["classes"].items(),
                         key=lambda kv: (-kv[1]["blocked"], kv[0])):
        L += [f"### `{cid}` — {e['blocked']} blocked", "",
              "**Candidate sources** (different org from the item's current citations):", ""]
        if e["candidates"]:
            for c in e["candidates"]:
                if c.get("error"):
                    L.append(f"- ERROR: {c['error']}")
                else:
                    L.append(f"- `{c['org']}` [{c.get('measured_state') or 'unmeasured'}] "
                             f"{c.get('source_type') or ''} {c['url']}")
        else:
            L.append("- none in the sourcebook")
        L += ["", "**Items**", ""]
        for item in e["items"]:
            orgs = ", ".join(f"`{o}`" for o in item["current_orgs"]) or "—"
            line = (f"- `{item['item_key']}` — **{item['blocker_class']}**; "
                    f"counted orgs: {orgs}")
            if item.get("builder_hosts"):
                line += ("; builder host(s) ignored: "
                         + ", ".join(f"`{h}`" for h in item["builder_hosts"]))
            L.append(line)
            L.append(f"  - gate: `{item.get('gate_reasons')}`")
            L.append(f"  - {item['claim']}")
        L.append("")
    return "\n".join(L).rstrip() + "\n"


def main() -> int:
    from wks import store

    con = store.open_db(create=False)
    doc = build(con)
    con.close()

    GAPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    md_path = GAPS / f"single-publisher-{stamp}.md"
    json_path = GAPS / f"single-publisher-{stamp}.json"
    md_path.write_text(markdown(doc), encoding="utf-8")
    json_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    s = doc["summary"]
    print(f"blocked items: {s['blocked_items']} across {s['classes']} classes")
    print(f"with a candidate: {s['items_with_candidate']}; "
          f"without: {s['items_without_candidate']}")
    print(f"wrote {md_path.relative_to(ROOT)}")
    print(f"wrote {json_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
