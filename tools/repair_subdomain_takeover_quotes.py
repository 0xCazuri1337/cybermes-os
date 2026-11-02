#!/usr/bin/env python
"""Repair the measured subdomain-takeover citation defect.

Twenty active subdomain-takeover items cited ``httpwg.org/specs/rfc6265.html``
(RFC 6265, HTTP cookies). For most of them the attached quote is about cookie
security, not subdomain takeover. That source was acting as a second publisher
in the gate's count, so a single real source plus one irrelevant source could
look like corroboration.

This tool:

* removes the wrong RFC 6265 link from every non-cookie item in the class;
* adds verified OWASP and Microsoft quotes to the two claims those sources
  actually support;
* leaves unsupported claims held rather than rewriting them or adding a
  decorative second source;
* marks the exact ``hth_`` and ``auto.t`` duplicates superseded, preserving
  every row.

It fetches live pages and verifies every quote with ``find_quote`` before any
write. Dry-run is the default.

    python tools/repair_subdomain_takeover_quotes.py
    python tools/repair_subdomain_takeover_quotes.py --apply
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import config, pipeline, quality, store  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

OWASP = ("https://cheatsheetseries.owasp.org/cheatsheets/"
         "Subdomain_Takeover_Prevention_Cheat_Sheet.html")
MS = ("https://learn.microsoft.com/en-us/azure/security/fundamentals/"
      "subdomain-takeover")
HTTPWG = "https://httpwg.org/specs/rfc6265.html"

QUOTES = {
    "owasp_intro": (
        OWASP,
        "Subdomain takeover is a vulnerability that occurs when a DNS record "
        "(typically a CNAME) points to a cloud resource or third-party service "
        "that has been deprovisioned or no longer exists.",
        "Subdomain Takeover Prevention Cheat Sheet",
        "cheatsheet",
    ),
    "ms_definition": (
        MS,
        "A subdomain takeover can occur when you have a DNS record that points "
        "to a deprovisioned Azure resource.",
        "Prevent dangling DNS entries and avoid subdomain takeover",
        "docs",
    ),
    "ms_dangling": (
        MS,
        "If it isn't deleted, it's a \"dangling DNS\" record and creates the "
        "possibility for subdomain takeover.",
        "Prevent dangling DNS entries and avoid subdomain takeover",
        "docs",
    ),
    "owasp_404": (
        OWASP,
        "Alert when new CNAME records are created and when target resources "
        "return errors such as HTTP 404, NXDOMAIN, or cloud provider default "
        "error pages.",
        "Subdomain Takeover Prevention Cheat Sheet",
        "cheatsheet",
    ),
    "owasp_tls": (
        OWASP,
        "An attacker controlling MX records can complete DV challenges and "
        "obtain legitimate TLS certificates for the subdomain, enabling "
        "transparent HTTPS phishing or man-in-the-middle attacks.",
        "Subdomain Takeover Prevention Cheat Sheet",
        "cheatsheet",
    ),
    "owasp_cname": (
        OWASP,
        "CNAME records are the most common vector. If the canonical name "
        "resolves to a service that can be claimed, takeover is possible.",
        "Subdomain Takeover Prevention Cheat Sheet",
        "cheatsheet",
    ),
}

# Items that get real second-publisher support. Claims are NOT rewritten.
ADD = {
    "subdomain_takeover.technique.ht_1_grab_all_subdomains_of_target_i": [
        "owasp_intro", "ms_definition"],
    "subdomain_takeover.prerequisite.ht_these_subdomains_use_a_cname_recor": [
        "owasp_intro", "ms_dangling"],
    "subdomain_takeover.auto.04": ["owasp_intro", "ms_definition"],
}

# Relevant partial support for held claims. These do not add a second counted
# publisher, so the claims remain under_review; the point is to keep the
# evidence that does exist instead of deleting the item.
ADD_HELD = {
    "subdomain_takeover.signal.ht_1_attached_to_a_third_party_domai": [
        "owasp_404"],
    "subdomain_takeover.impact.ht_a_domain_owner_will_be_unaware_of": [
        "owasp_tls"],
    "subdomain_takeover.variant.ht_subs_or_top_level_domain_cname": [
        "owasp_cname"],
}

# The cookie RFC is genuinely relevant to this chain link; do not remove it.
KEEP_HTTPWG = {
    "subdomain_takeover.chain_link.session_cookie_domain_scope_to_attacker_host",
}

DUPES = {
    # duplicate key -> canonical key
    "subdomain_takeover.impact.hth_a_domain_owner_will_be_unaware_of":
        "subdomain_takeover.impact.ht_a_domain_owner_will_be_unaware_of",
    "subdomain_takeover.prerequisite.hth_these_subdomains_use_a_cname_recor":
        "subdomain_takeover.prerequisite.ht_these_subdomains_use_a_cname_recor",
    "subdomain_takeover.signal.hth_1_attached_to_a_third_party_domai":
        "subdomain_takeover.signal.ht_1_attached_to_a_third_party_domai",
    "subdomain_takeover.technique.hth_1_grab_all_subdomains_of_target_i":
        "subdomain_takeover.technique.ht_1_grab_all_subdomains_of_target_i",
    "subdomain_takeover.variant.hth_subs_or_top_level_domain_cname":
        "subdomain_takeover.variant.ht_subs_or_top_level_domain_cname",
    "subdomain_takeover.auto.t.3a40551c": "subdomain_takeover.auto.01",
    "subdomain_takeover.auto.t.31ef2d3a": "subdomain_takeover.auto.02",
    "subdomain_takeover.auto.t.c606fec2": "subdomain_takeover.auto.03",
    "subdomain_takeover.auto.t.0f664070": "subdomain_takeover.auto.04",
}


def _source_id(con, url: str) -> int | None:
    row = con.execute("SELECT id FROM source WHERE url=?", (url,)).fetchone()
    return int(row["id"]) if row else None


def _item(con, key: str):
    row = con.execute("SELECT * FROM item WHERE item_key=?", (key,)).fetchone()
    if row is None:
        raise SystemExit(f"missing item: {key}")
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(ROOT / "db" / "wks.db"))
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    con = store.open_db(Path(args.db), create=False)

    # Verify every quote live before writing anything.
    fetched: dict[str, dict[str, Any]] = {}
    for name, (url, quote, title, source_type) in QUOTES.items():
        got = pipeline.fetch(url, limit=1_500_000)
        if got.get("access_state") != "ACTIVE":
            raise SystemExit(f"{name}: page not ACTIVE: {got.get('access_state')}")
        if not find_quote(got.get("text") or "", quote):
            raise SystemExit(f"{name}: quote NOT found live at {url}")
        fetched[name] = {"got": got, "quote": quote, "url": url,
                         "title": title, "source_type": source_type}

    # Compute the plan before touching the DB.
    all_non_cookie = [
        r["item_key"] for r in con.execute(
            """SELECT i.item_key
               FROM item i
               JOIN quality q ON q.item_id=i.id
               WHERE i.class_id='subdomain_takeover' AND i.status='active'
                 AND EXISTS (
                   SELECT 1 FROM item_source x JOIN source s ON s.id=x.source_id
                   WHERE x.item_id=i.id AND s.url=?)
               ORDER BY i.item_key""", (HTTPWG,)).fetchall()
        if r["item_key"] not in KEEP_HTTPWG
    ]
    print(f"items with the wrong RFC 6265 link: {len(all_non_cookie)}")
    for key in all_non_cookie:
        print(f"  unlink {key}")
    add_plan = {**ADD, **ADD_HELD}
    for key, names in add_plan.items():
        print(f"  add to {key}: {', '.join(names)}")
    for key, canonical in DUPES.items():
        print(f"  supersede duplicate {key} -> {canonical}")

    if not args.apply:
        print("dry run; pass --apply to write")
        con.close()
        return 0

    before = {r["item_key"]: r["validation_state"] for r in con.execute(
        """SELECT i.item_key, q.validation_state
           FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.class_id='subdomain_takeover'""").fetchall()}

    try:
        httpwg_id = _source_id(con, HTTPWG)
        if httpwg_id is None:
            raise SystemExit("RFC 6265 source row is missing")
        for key in all_non_cookie:
            item = _item(con, key)
            store.unlink_source(con, int(item["id"]), httpwg_id)

        for key, names in add_plan.items():
            item = _item(con, key)
            for name in names:
                spec = fetched[name]
                host = store.host_of(spec["url"])
                sid = store.upsert_source(
                    con, spec["url"], host,
                    title=spec["title"],
                    publisher=config.publisher_org(host),
                    source_type=spec["source_type"],
                    content_hash=spec["got"].get("content_hash"),
                    http_status=spec["got"].get("http_status"),
                    access_state=spec["got"].get("access_state"),
                    access_checked_at=store.now(),
                    access_detail="quote verified during subdomain-takeover repair",
                )
                store.link_source(
                    con, int(item["id"]), sid, quote=spec["quote"],
                    locator="verified live quote; repair 2026-10-28",
                )

        for key, canonical in DUPES.items():
            row = _item(con, key)
            can = _item(con, canonical)
            con.execute(
                "UPDATE item SET status='superseded', dedup_of=?, canonical_id=?, "
                "updated_at=? WHERE id=?",
                (int(can["id"]), int(can["id"]), store.now(), int(row["id"])),
            )

        con.commit()
    except Exception:
        con.rollback()
        raise

    after = {}
    changed = []
    for key in add_plan:
        item = _item(con, key)
        verdict = quality.assess(con, int(item["id"]))
        store.set_state(con, int(item["id"]), verdict["state"],
                        verdict["score"], verdict["reasons"])
        after[key] = verdict["state"]
        changed.append((key, before.get(key), verdict["state"],
                        verdict["reasons"]))
    con.commit()
    for key, old, new, reasons in changed:
        print(f"{key}: {old} -> {new} {reasons}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
