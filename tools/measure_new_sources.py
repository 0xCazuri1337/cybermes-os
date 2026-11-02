"""Measure every UNVERIFIED source, in one pass, and record the result.

WHY THIS EXISTS. `wks.source_intake --apply` adds sources that have been fetched
once by the intake gate, but the store's `source.access_state` is a SEPARATE
census written only by `verify_quotes --record`, `verify_sources --apply` and
`staleness --apply`. New rows therefore enter as `UNVERIFIED` and immediately
dilute `sourcegate.verification_summary()`.

MEASURED three times in one session: adding 44 sources dropped coverage to
88.9%, adding 33 dropped it to 94.5%, both failing `test_wks_sources`'s 95%
threshold. Each time the correct response was to MEASURE the rows, never to
lower the bar — and each time it took a manual round trip that should not have
been necessary.

So this is the standing post-intake step. It is idempotent, reports what it
measured, and prints the resulting coverage percentage so the drop is visible
immediately rather than at the next test run.

    python tools/measure_new_sources.py            # measure, print census
    python tools/measure_new_sources.py --report   # census only, no fetching
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402
from wks import pipeline  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true",
                    help="print the census without fetching")
    a = ap.parse_args()

    con = store.connect(config.DB_PATH)
    try:
        if not a.report:
            rows = con.execute(
                "SELECT id, url FROM source WHERE access_state='UNVERIFIED'"
            ).fetchall()
            ok = other = 0
            for r in rows:
                try:
                    p = pipeline.fetch(r["url"], limit=1_500_000)
                    st = p.get("access_state", "UNVERIFIED")
                    if st == "ACTIVE":
                        con.execute(
                            "UPDATE source SET access_state='ACTIVE', "
                            "http_status=?, content_hash=?, "
                            "last_ok_at=datetime('now') WHERE id=?",
                            (p.get("status"), p.get("content_hash"), r["id"]))
                        ok += 1
                    else:
                        con.execute(
                            "UPDATE source SET access_state=?, access_detail=? "
                            "WHERE id=?",
                            (st, str(p.get("error") or p.get("status"))[:90],
                             r["id"]))
                        other += 1
                except Exception as exc:                          # noqa: BLE001
                    con.execute(
                        "UPDATE source SET access_state='BLOCKED', "
                        "access_detail=? WHERE id=?",
                        (f"{type(exc).__name__}: {exc}"[:90], r["id"]))
                    other += 1
            con.commit()
            print(f"measured {len(rows)} unverified source(s): "
                  f"ACTIVE={ok} other={other}")

        census = {r["access_state"]: r["n"] for r in con.execute(
            "SELECT access_state, COUNT(*) n FROM source GROUP BY 1")}
        total = sum(census.values())
        active = census.get("ACTIVE", 0)
        pct = round(100.0 * active / total, 1) if total else 0.0
        for k, v in sorted(census.items(), key=lambda kv: -kv[1]):
            print(f"  {str(k):14s} {v}")
        print(f"  coverage: {pct}%  (test_wks_sources requires > 95%)")
        if not a.report and pct <= 95.0:
            print("  WARNING: coverage still below the threshold — these are "
                  "genuinely unusable sources, not unmeasured ones.")
            return 1
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
