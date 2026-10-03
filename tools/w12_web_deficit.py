"""Pick the weakest WEB-domain class by MEASURED deficit, not by intuition.

Reads the canonical db through store.open_db() -- never sqlite3.connect(<root>/
wks.db): the real store is db/wks.db and a root-level wks.db is a 0-byte file a
stray connect CREATES (it happened while writing this tool).

Reports per web class: items, supported items, fp_case rows, chains.

Two schema traps this encodes:
  * validation_state lives in `quality`, not `item`  (skill: "validation_state
    lives in quality, not item" -- filtering item.* returns a clean EMPTY report).
  * `chain` has no class_id; chains are keyed by chain_key globally, so a
    per-class chain count must go through chain_step -> item.
"""
import os
import sqlite3
import sys

WKS = os.environ.get("WKS_ROOT", "C:/Users/Administrator/.hermes/cyber")
sys.path.insert(0, WKS)

from wks import config, domains, store  # noqa: E402

VALIDATED = ("supported", "high_confidence")
THIN, WEAK_PCT = 15, 35.0


def counts(con, cid):
    q = "SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id WHERE i.class_id=?"
    items = con.execute("SELECT COUNT(*) FROM item WHERE class_id=?", (cid,)).fetchone()[0]
    sup = con.execute(q + " AND q.validation_state IN (?,?)", (cid, *VALIDATED)).fetchone()[0]
    fp = con.execute("SELECT COUNT(*) FROM fp_case WHERE class_id=?", (cid,)).fetchone()[0]
    return items, sup, fp


def chains_for(con, cid):
    """Chains are global; per-class membership is via chain_step -> item."""
    return con.execute(
        """SELECT COUNT(DISTINCT s.chain_id) FROM chain_step s
           JOIN item i ON i.id = s.item_id WHERE i.class_id=?""",
        (cid,),
    ).fetchone()[0]


def main():
    con = store.open_db()
    con.row_factory = sqlite3.Row
    path = str(config.db_path())  # store.Path is the pathlib CLASS, not an instance
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        raise SystemExit(f"canonical db missing or 0 bytes: {path}")
    print(f"db: {path} ({os.path.getsize(path):,} bytes)\n")

    cids, unmapped = [], []
    for r in con.execute("SELECT class_id FROM class_domain ORDER BY class_id"):
        cid = r["class_id"]
        try:
            dom = domains.domain_of(con, cid)
        except Exception as exc:  # unmapped surface -> resolver RAISES
            unmapped.append((cid, str(exc)))
            continue
        if dom == "web":
            cids.append(cid)

    rows = []
    for cid in cids:
        items, sup, fp = counts(con, cid)
        ch = chains_for(con, cid)
        st = con.execute("SELECT status FROM bug_class WHERE id=?", (cid,)).fetchone()
        rows.append((cid, st["status"] if st else "?", items, sup, fp, ch))

    rows.sort(key=lambda t: (t[2], -t[3]))
    hdr = f"{'class':32s} {'status':12s} {'items':>5s} {'sup':>4s} {'fp':>3s} {'chn':>3s}  {'sup%':>5s}"
    print(hdr)
    print("-" * len(hdr))
    for cid, status, items, sup, fp, ch in rows:
        pct = sup / items * 100 if items else 0.0
        print(f"{cid:32s} {status:12s} {items:5d} {sup:4d} {fp:3d} {ch:3d}  {pct:4.0f}%")

    thin = [r for r in rows if r[2] < THIN]
    weak = [r for r in rows if r[2] >= THIN and (r[3] / r[2] * 100) < WEAK_PCT]
    print(f"\nweb classes routed: {len(cids)}   unmapped surfaces: {len(unmapped)}")
    for cid, why in unmapped:
        print(f"  UNMAPPED {cid}: {why}")
    print(f"\nTHIN (<{THIN} items): " + (", ".join(f"{r[0]}({r[2]})" for r in thin) or "none"))
    print(f"WEAK CORROBORATION (>={THIN} items, <{WEAK_PCT:.0f}% supported):")
    if weak:
        for r in weak:
            print(f"  {r[0]:32s} {r[3]}/{r[2]} = {r[3]/r[2]*100:.0f}%")
    else:
        print("  none")


if __name__ == "__main__":
    main()