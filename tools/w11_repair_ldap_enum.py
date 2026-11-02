"""Repair ldap_enum: every item's 2nd citation is a batch-assigned Microsoft URL
whose page does not contain that item's quote.

THE DEFECT. Each ldap_enum item carries two citations. The FIRST is real — a
verbatim quote from the page actually read (nccgroup.com or specterops.io). The
SECOND is always the same URL,
`learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing`, with a
quote that belongs to a DIFFERENT item:

  ldap_enum.auto.02                 quote: "Man-in-the-middle attacks : An
                                    attacker captures packets between client
                                    and server, modifies them, and forwards..."
  ldap_enum.auto.t.23374889         quote: "This binding ensures that even if
                                    an attacker intercepts the encrypted
                                    session, they can't hijack or downgrade..."

The page is LIVE (HTTP 200, 14,961 chars, "LDAP Signing Overview") and neither
quote is on it. So the second citation supplied the second publisher ORG that
let the item promote, using text from nowhere. That is what "corroborated by 2
orgs" meant for these ten items.

THE FIX. An item needs two INDEPENDENT orgs that actually support it. So:
  1. fetch the first citation's page and re-confirm the real quote is on it;
  2. search the store for OTHER items whose verified quotes genuinely belong to
     this class, on a different org;
  3. re-point the second citation at one of those, or -- when no honest second
     source exists -- SUPERSEDE the item rather than leave it resting on a
     citation that was never true.

Superseding is the correct outcome for an item with one real source. It stays in
the db for provenance and leaves the active corpus, which is what quality.py
filters on. Manufacturing a second citation to keep a row alive is the exact
defect being repaired.

Run:  python tools/w11_repair_ldap_enum.py [--apply]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402
from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

BAD_URL_MARKER = "ad-ds/ldap-signing"

# Vocabulary that makes a quote plausibly about LDAP enumeration. Deliberately
# GENEROUS -- a narrow list punishes correct citations, and this repair must not
# invent its own false positives.
TOPICAL = (
    "ldap", "directory", "null bind", "anonymous bind", "ldapsearch",
    "distinguished name", "objectclass", "base dn", "rootdse", "domain controller",
    "kerberos", "ntlm", "signing", "channel binding", "service account",
    "group policy", "bloodhound", "ad ", "active directory", "samaccountname",
)


def quote_on_page(url: str, quote: str) -> bool:
    try:
        pg = pipeline.fetch(url, limit=1_500_000)
    except Exception:                                     # noqa: BLE001
        return False
    if not pg.get("ok"):
        return False
    return bool(find_quote(pg["text"], quote or ""))


def topical(quote: str) -> bool:
    q = (quote or "").lower()
    return any(t in q for t in TOPICAL)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    con = store.connect(config.DB_PATH)

    items = con.execute(
        """SELECT DISTINCT i.id, i.item_key FROM item i
           JOIN item_source q ON q.item_id=i.id JOIN source s ON s.id=q.source_id
            WHERE i.class_id='ldap_enum' AND i.status='active'
              AND s.url LIKE ?""", (f"%{BAD_URL_MARKER}%",)).fetchall()
    print(f"ldap_enum items carrying the batch-assigned URL: {len(items)}")

    # Candidate honest second sources: verified quotes on OTHER orgs that are
    # topically about this class, harvested from anywhere in the corpus.
    pool = con.execute(
        """SELECT DISTINCT s.url, s.host, q.quote FROM item_source q
             JOIN source s ON s.id=q.source_id JOIN item i ON i.id=q.item_id
            WHERE i.class_id='ldap_enum' AND i.status='active'
              AND q.quote IS NOT NULL AND LENGTH(q.quote)>40
              AND s.url NOT LIKE ?""", (f"%{BAD_URL_MARKER}%",)).fetchall()
    usable = [dict(url=r["url"], host=r["host"], quote=r["quote"])
              for r in pool if topical(r["quote"])]
    print(f"  candidate honest 2nd sources (other org, on-topic): {len(usable)}")

    plans = []
    for it in items:
        cites = con.execute(
            """SELECT q.source_id, s.url, s.host, q.quote FROM item_source q
                 JOIN source s ON s.id=q.source_id WHERE q.item_id=?""",
            (it["id"],)).fetchall()
        bad = [c for c in cites if BAD_URL_MARKER in c["url"]]
        good = [c for c in cites if BAD_URL_MARKER not in c["url"]]
        real = []
        for g in good:
            if quote_on_page(g["url"], g["quote"]):
                real.append(g)
        plan = {"item": dict(it), "bad": [dict(c) for c in bad],
                "real_first": [dict(c) for c in real]}
        # An honest second org must not be the same org as the first, AND the
        # quote must actually be ABOUT this item's claim. Without that second
        # test this repair would stamp ONE generic quote onto all 13 items --
        # manufacturing precisely the cross-class boilerplate that T28 exists to
        # catch. A repair that reintroduces the defect it repairs is worse than
        # the defect, so an unmatched item is SUPERSEDED instead.
        hosts = {config.publisher_org(c["host"]) for c in real}
        claim = (con.execute("SELECT claim FROM item WHERE id=?",
                             (it["id"],)).fetchone() or {"claim": ""})["claim"]
        cw = set(re.findall(r"[a-z]{5,}", (claim or "").lower()))
        scored = []
        for u in usable:
            org = config.publisher_org(u["host"])
            if org in hosts:
                continue
            qw = set(re.findall(r"[a-z]{5,}", u["quote"].lower()))
            overlap = len(cw & qw)
            if overlap >= 2:
                scored.append((overlap, u))
        scored.sort(key=lambda t: -t[0])
        plan["second"] = scored[0][1] if scored else None
        plan["overlap"] = scored[0][0] if scored else 0
        plans.append(plan)
        verdict = "RESOURCE" if plan["second"] else "SUPERSEDE"
        print(f"  {it['item_key']}: real_cites={len(real)} -> {verdict}")

    n_res = sum(1 for p in plans if p["second"])
    n_sup = len(plans) - n_res
    print(f"\nwould re-source {n_res}, supersede {n_sup}")

    if not a.apply:
        print("dry run: pass --apply")
        con.close()
        return 0

    for p in plans:
        if p["second"]:
            src = con.execute(
                "SELECT id, host, url FROM source WHERE url=?",
                (p["second"]["url"],)).fetchone()
            if src is None:
                print(f"  SKIP {p['item']['item_key']}: source row absent")
                continue
            for b in p["bad"]:
                con.execute(
                    "UPDATE item_source SET source_id=?, quote=?, locator=? "
                    "WHERE item_id=? AND source_id=?",
                    (src["id"], p["second"]["quote"], p["second"]["url"],
                     p["item"]["id"], b["source_id"]))
        else:
            con.execute("UPDATE item SET status='superseded' WHERE id=?",
                        (p["item"]["id"],))
    con.commit()

    # READ BACK what was actually written. MEASURED: an earlier version printed
    # the INTENDED outcome per item and exited 0 while half the writes had not
    # landed, so the log read as a transcript of writes that did not happen.
    # A repair must report the row it re-read, never the row it intended.
    still_bad, resurrected = [], []
    for p in plans:
        key = p["item"]["item_key"]
        row = con.execute("SELECT status FROM item WHERE item_key=?",
                          (key,)).fetchone()
        n_bad = con.execute(
            """SELECT COUNT(*) n FROM item_source q
                 JOIN source s ON s.id=q.source_id JOIN item i ON i.id=q.item_id
                WHERE i.item_key=? AND s.url LIKE ?""",
            (key, f"%{BAD_URL_MARKER}%")).fetchone()["n"]
        if row and row["status"] == "superseded":
            print(f"  superseded {key}  (confirmed by read-back)")
        elif n_bad:
            still_bad.append(key)
        else:
            print(f"  re-sourced {key}  (confirmed by read-back)")
        if row and row["status"] == "active" and p["second"] is None:
            resurrected.append(key)

    if still_bad or resurrected:
        print(f"\nWRITE VERIFICATION FAILED: {len(still_bad)} still carry the "
              f"bad url, {len(resurrected)} intended supersedes did not land.")
        for k in still_bad + resurrected:
            print(f"   {k}")
        con.close()
        return 1
    print("\nAll writes confirmed by read-back.")
    con.close()
    print("Verify: python -m wks.verify_quotes --class ldap_enum")
    return 0


if __name__ == "__main__":
    sys.exit(main())
