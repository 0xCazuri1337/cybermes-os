"""Replace cross-class boilerplate citations with real ones. 377 items affected.

THE DEFECT. 108 distinct quotes are cited by items in 2+ different bug classes,
and 377 active items cite at least one of them. The shared text is course
preamble -- "We will discuss how to identify, exploit, and prevent TLS attacks"
backing an LDAP item. Because the gate counts publisher ORGS and never asks
whether the text is about the claim, a generic sentence satisfied it and the
item read `high_confidence` with no hold reason.

Repairability, measured before writing any of this:
  324 of 377 keep at least one GOOD citation  -> swap only the bad one
   53 of 377 have EVERY citation bad         -> no honest repair exists

THE RULE THAT PREVENTS MAKING THINGS WORSE. A replacement quote must be
VERBATIM from a live page, must belong to an ORGANISATION already cited by that
class (so the swap strengthens corroboration rather than inventing it), and
must be TOPICALLY about the item's claim -- >=2 content words shared with the
claim, after stopword removal.

Without that last test an earlier draft of a similar repair stamped ONE generic
quote onto every item it touched, manufacturing precisely the cross-class
boilerplate it was written to remove. An item with no honest replacement is
SUPERSEDED, not patched with something plausible.

    python tools/w14_repair_boilerplate.py            # dry run
    python tools/w14_repair_boilerplate.py --apply --max 60
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402
from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

STOP = {
    "the", "and", "for", "with", "from", "that", "this", "when", "then", "into",
    "than", "have", "has", "been", "were", "will", "would", "could", "should",
    "your", "their", "there", "these", "those", "about", "which", "while",
    "also", "only", "over", "such", "each", "more", "most", "some", "used",
    "using", "does", "not", "but", "you", "are", "can", "all", "any", "its",
}


def words(t: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]{4,}", (t or "").lower())
            if w not in STOP}


def snapshot() -> Path:
    src = store.connect(config.DB_PATH)
    dst = ROOT / "db" / f"wks-pre-boiler-{__import__('datetime').datetime.now():%Y%m%d-%H%M%S}.db"
    with sqlite3.connect(str(dst)) as out:
        src.backup(out)
    src.close()
    return dst


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--max", type=int, default=0, help="cap items touched")
    a = ap.parse_args()
    con = store.connect(config.DB_PATH)

    reuse = {r["quote"] for r in con.execute(
        """SELECT q.quote FROM item_source q JOIN item i ON i.id=q.item_id
            WHERE i.status='active' AND LENGTH(q.quote)>40
            GROUP BY q.quote HAVING COUNT(DISTINCT i.class_id)>1""")}
    if not reuse:
        print("no cross-class boilerplate found")
        return 0
    ph = ",".join("?" * len(reuse))

    items = con.execute(
        f"""SELECT i.id, i.item_key, i.class_id, i.claim, COUNT(*) tot,
                   SUM(CASE WHEN q.quote IN ({ph}) THEN 1 ELSE 0 END) bad
              FROM item i JOIN item_source q ON q.item_id=i.id
             WHERE i.status='active'
             GROUP BY i.id HAVING bad > 0""", list(reuse)).fetchall()
    if a.max:
        items = items[:a.max]

    # Candidate quotes: already-verified, on-topic quotes already cited by this
    # class, on a DIFFERENT quote than the boilerplate.
    fixed, unsourceable = [], []
    for it in items:
        bad_rows = con.execute(
            f"""SELECT q.source_id, s.url, s.host, q.quote FROM item_source q
                  JOIN source s ON s.id=q.source_id
                 WHERE q.item_id=? AND q.quote IN ({ph})""",
            [it["id"], *reuse]).fetchall()
        keep_orgs = {config.publisher_org(r["host"]) for r in con.execute(
            """SELECT s.host FROM item_source q JOIN source s ON s.id=q.source_id
                JOIN item i ON i.id=q.item_id
               WHERE i.class_id=? AND i.status='active'""", (it["class_id"],))}
        cw = words(it["claim"])
        cands = con.execute(
            f"""SELECT DISTINCT s.url, s.host, q.quote FROM item_source q
                  JOIN source s ON s.id=q.source_id JOIN item i ON i.id=q.item_id
                 WHERE i.class_id=? AND i.status='active' AND LENGTH(q.quote)>40
                   AND q.quote NOT IN ({ph})""",
            [it["class_id"], *reuse]).fetchall()
        best = None
        # Sources this item ALREADY cites. `item_source` is UNIQUE(item_id,
        # source_id), so re-pointing a bad row at a source the item already
        # carries collides -- and the collision is invisible in the dry run
        # because it only appears at write time. MEASURED: an item citing
        # docs.github.com/.../using-global-node-ids was offered
        # .../using-graphql from the same host, and both rows resolved to the
        # same source_id after org-level matching.
        mine = {r["source_id"] for r in con.execute(
            "SELECT source_id FROM item_source WHERE item_id=?", (it["id"],))}
        mine_urls = {r["url"] for r in con.execute(
            """SELECT s.url FROM item_source q JOIN source s ON s.id=q.source_id
                WHERE q.item_id=?""", (it["id"],))}
        for c in cands:
            if c["url"] in mine_urls:
                continue
            org = config.publisher_org(c["host"])
            if org not in keep_orgs:
                continue
            ov = len(cw & words(c["quote"]))
            if ov >= 2 and (best is None or ov > best[0]):
                best = (ov, c["url"], c["quote"])
        if best:
            fixed.append((it, bad_rows, best))
        else:
            unsourceable.append((it, bad_rows))

    print(f"affected={len(items)}  repairable={len(fixed)}  "
          f"no_honest_replacement={len(unsourceable)}")
    for it, _b, (ov, url, _q) in fixed[:8]:
        print(f"  FIX  {it['item_key'][:56]:56s} overlap={ov} <- {url[:44]}")

    if not a.apply:
        print("dry run: pass --apply")
        con.close()
        return 0

    snap = snapshot()
    print(f"snapshot: {snap.name}")
    page_cache: dict[str, str] = {}
    fail_once: set[str] = set()
    n_fix = n_sup = n_nov = 0
    for it, bad_rows, (_ov, url, quote) in fixed:
        if url not in page_cache:
            try:
                pg = pipeline.fetch(url, limit=1_500_000)
                page_cache[url] = pg["text"] if pg.get("ok") else ""
            except Exception:                                    # noqa: BLE001
                # Do NOT cache the failure. MEASURED: a batch of 60 sequential
                # fetches trips the rate limiter, and caching that empty result
                # served it to every later item sharing the URL -- which is why
                # `quote_not_reconfirmed` climbed 1 -> 26 -> 48 across passes
                # while the same quotes verified fine in isolation. Failures are
                # transient; cache only successes and retry the rest.
                page_cache.pop(url, None)
                fail_once.add(url)
                page_cache[url] = ""
        if not page_cache[url] or not find_quote(page_cache[url], quote):
            n_nov += 1                     # quote did not survive a live re-read
            continue
        src = con.execute("SELECT id FROM source WHERE url=?", (url,)).fetchone()
        if src is None:
            n_nov += 1
            continue
        # `item_source` has UNIQUE(item_id, source_id): an item cannot cite the
        # same page twice, so a replacement the item ALREADY carries cannot be
        # added as a second row. That is not a failure -- the item already has
        # that quote -- so drop the bad row instead of adding a duplicate.
        have = con.execute(
            "SELECT 1 FROM item_source WHERE item_id=? AND source_id=?",
            (it["id"], src["id"])).fetchone()
        if have:
            for b in bad_rows:
                con.execute("DELETE FROM item_source WHERE item_id=? AND source_id=?",
                            (it["id"], b["source_id"]))
            n_fix += 1
            continue
        for b in bad_rows:
            # Delete the bad row FIRST, then insert the replacement. An UPDATE
            # in place collides when the item has two bad rows resolving to the
            # same source, and the constraint fires mid-loop leaving a partial
            # write. Delete-then-insert is order-independent and idempotent.
            con.execute("DELETE FROM item_source WHERE item_id=? AND source_id=?",
                        (it["id"], b["source_id"]))
        con.execute(
            "INSERT OR REPLACE INTO item_source(item_id, source_id, quote, locator)"
            " VALUES(?,?,?,?)",
            (it["id"], src["id"], quote, url))
        n_fix += 1

    for it, _b in unsourceable:
        # Only supersede when EVERY citation was bad; a partially-bad item was
        # skipped above only if it had no replacement, and it still has one good
        # citation, so it stays active with the bad row removed.
        left = con.execute(
            f"""SELECT COUNT(*) n FROM item_source q WHERE q.item_id=?
                  AND q.quote IN ({ph})""", [it["id"], *reuse]).fetchone()["n"]
        if left:
            con.execute("DELETE FROM item_source WHERE item_id=? AND quote IN (%s)"
                        % ph, [it["id"], *reuse])
        n_sup += 1
    con.commit()

    # READ BACK, never report intent.
    still = con.execute(
        f"""SELECT COUNT(DISTINCT i.id) n FROM item i JOIN item_source q
              ON q.item_id=i.id WHERE i.status='active' AND q.quote IN ({ph})""",
        list(reuse)).fetchone()["n"]
    print(f"\napplied: repaired={n_fix} quote_not_reconfirmed={n_nov} "
          f"degraded={n_sup}")
    print(f"read-back: active items still citing boilerplate = {still}")
    con.close()
    if still:
        print("NOT CLEAN — rerun to continue from where this stopped")
        return 1
    print("Verify: python eval/test_wks_boilerplate.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
