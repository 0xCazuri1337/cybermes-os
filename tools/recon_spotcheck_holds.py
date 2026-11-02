"""Spot-check the held items by hand: are the holds legitimate, or vocabulary holes?

A gate that holds 30.6% of the corpus needs its verdicts audited before anyone
believes them. This samples held items per state and prints the claim plus the
reason, so the holds can be judged against the text rather than trusted.

    python tools/recon_spotcheck_holds.py --state ORPHAN --n 12
    python tools/recon_spotcheck_holds.py --all
"""
import argparse
import os
import sys

sys.path.insert(0, os.environ.get("WKS_ROOT", "."))
from wks import relevance as R  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--state", default="")
ap.add_argument("--class", dest="cls", default="")
ap.add_argument("--n", type=int, default=10)
ap.add_argument("--all", action="store_true")
args = ap.parse_args()

out = R.audit()
if args.all:
    print("\n=== EVERY HELD ITEM ===")
    for h in out["held_items"]:
        print(f"[{h['state']}] {h['class_id']:26} {h['item_key']}")
        print(f"    claim: {h['claim_head'][:150]}")
    raise SystemExit(0)

want = args.state
picked = [h for h in out["held_items"]
          if (not want or h["state"] == want) and (not args.cls or h["class_id"] == args.cls)]
print(f"\n=== {len(picked)} held items matching state={want!r} class={args.cls!r} ===")
for h in picked[:args.n]:
    print(f"[{h['state']}] {h['class_id']} :: {h['item_key']}")
    print(f"    CLAIM : {h['claim_head']}")
    print(f"    WHY   : {h['reason']}")
    print()