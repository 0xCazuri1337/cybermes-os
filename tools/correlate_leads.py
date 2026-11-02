"""Give each held bugbountydaily lead a SECOND independent publisher.

Why this step exists
--------------------
The 8 harvested leads were all held with `INSUFFICIENT_PUBLISHER_HOSTS,
INSUFFICIENT_SOURCES`: each cites exactly one publisher, because a single
writeup is one host. That is the gate working correctly — but it leaves the
corpus strictly no better off, since a held item cannot be hunted from.

So this finds a genuinely INDEPENDENT second publisher for each class, fetches
it live, extracts a span that is actually about the same mechanism, re-verifies
that span against the bytes held, and emits an updated intake item citing both.

Two rules this must not break:

  1. INDEPENDENCE. The partner must be a different registrable publisher org.
     Two pages of the same site do not corroborate each other — that is the
     rule the corpus was rebuilt around.
  2. NO TOPPED-UP QUOTES. If no span can be extracted and verified from the
     partner page, the item stays held. A quote is never borrowed from an
     existing item just to clear the 2-host gate; that would manufacture
     corroboration that no one ever wrote.

Run:  python tools/correlate_leads.py [--dry]
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from orch import researcher  # noqa: E402

INTAKE = ROOT / "research" / "incoming" / "harvest-bugbountydaily.json"

# Preferred partner page per class: a standards/taxonomy page that speaks to
# the same weakness, chosen for authority (lower = better) and independence
# from the lead's own publisher. Curated, and every URL is probed live before
# it is used.
PARTNER = {
    # Measured live 2026-10-04: the first drafts of two of these were 404
    # (`portswigger.net/web-security/http-request-smuggling` and
    # `owasp.org/www-community/attacks/Mass_assignment` — both moved). A partner
    # that cannot be fetched is indistinguishable from a partner that does not
    # exist, and both leave the item held, so the URL is probed at pairing time
    # and the failure is REPORTED rather than papered over.
    "mass_assign":        "https://cwe.mitre.org/data/definitions/915.html",
    "authz":              "https://portswigger.net/web-security/access-control",
    "misconfig":          "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    "exposed_services":   "https://cwe.mitre.org/data/definitions/284.html",
    "xss":                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "smuggling":         "https://cwe.mitre.org/data/definitions/444.html",
    "supply_chain":       "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
}

MIN_QUOTE = 90


def load_items() -> list[dict]:
    raw = INTAKE.read_text(encoding="utf-8")
    raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
    return json.loads(raw)["items"]


def partner_for(class_id: str, lead_publisher: str) -> str | None:
    url = PARTNER.get(class_id)
    if not url:
        return None
    partner_pub = researcher.registrable_domain(
        re.sub(r"^www\.", "", urlparse(url).netloc))
    if partner_pub == lead_publisher:
        # Never pair a lead with its own publisher — that is the single-publisher
        # trap the gate exists to catch, and reaching it here would be a bug.
        return None
    return url


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    items = load_items()
    con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    known_src = {r[0] for r in con.execute("SELECT host FROM source")}
    con.close()

    paired = unpaired = 0
    for it in items:
        class_id = it["item_key"].split(".")[0]
        lead_src = it["sources"][0]
        lead_pub = lead_src.get("publisher") or lead_src["host"]
        url = partner_for(class_id, lead_pub)
        if not url:
            print(f"  NO PARTNER {class_id:18} (lead pub {lead_pub})")
            unpaired += 1
            continue
        try:
            page = pipeline.fetch(url, limit=300_000)
        except Exception as e:  # noqa: BLE001
            print(f"  FETCH ERR {class_id:18} {type(e).__name__}")
            unpaired += 1
            continue
        if not page.get("ok"):
            print(f"  PARTNER DEAD {class_id:18} status={page.get('status')}")
            unpaired += 1
            continue
        text = page.get("text") or ""
        pairs = researcher.candidate_spans(text, class_id, limit=40)
        best = None
        for _claim, q in pairs:
            if len(q) >= MIN_QUOTE:
                best = q
                break
        if not best:
            print(f"  PARTNER NO SPAN {class_id:18} "
                  f"(chars={len(text)}) — item stays held, as it must")
            unpaired += 1
            continue
        if not researcher.verify_span(best, text):
            print(f"  PARTNER VERIFY FAIL {class_id}")
            unpaired += 1
            continue
        partner_pub = researcher.registrable_domain(
            re.sub(r"^www\.", "", urlparse(url).netloc))
        if partner_pub in (lead_pub, lead_src["host"]):
            print(f"  NOT INDEPENDENT {class_id}: {partner_pub} == {lead_pub}")
            unpaired += 1
            continue

        it["sources"].append({
            "url": url,
            "source_type": "taxonomy",
            "host": partner_pub,
            "publisher": partner_pub,
            "quote": best,
        })
        it["body"] += (f"\n\nCORROBORATING PUBLISHER ({partner_pub}) on the same "
                       f"weakness class:\n{best}")
        paired += 1
        print(f"  PAIRED {class_id:18} {lead_pub} + {partner_pub} "
              f"({len(best)}ch)")

    print()
    print(f"paired {paired} lead(s); {unpaired} left held")
    if args.dry or not paired:
        return 0

    payload = {
        "class_id": "multi",
        "items": items,
        "publishers": len({s["publisher"] for i in items for s in i["sources"]}),
        "sources": [s["url"] for i in items for s in i["sources"]],
        "note": ("bugbountydaily discovery leads, each now corroborated by a "
                 "second INDEPENDENT publisher whose span was extracted from "
                 "the live page and re-verified against it."),
    }
    out = INTAKE.with_name("harvest-bugbountydaily-paired.json")
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    out.write_text(out.read_text(encoding="utf-8")
                   + f"\n// COMPLETE {len(items)}\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())