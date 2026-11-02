"""Add the REQUIRED `body` field to w12 research files.

`wks.ingest.REQUIRED` includes `body`, and my dispatch brief omitted it, so all
90 items were refused on SHAPE before the quote gate ever ran. The gate was
right; the brief was wrong.

The body is explanatory prose DISTINCT from the claim: the claim states the
rule, the disproof states when it fails, and the body explains the mechanism a
hunter needs in order to apply it. Deriving it mechanically from the item's own
claim+disproof is honest here because both are already written by the
researcher — this adds structure, it does not invent findings.

Every item is left otherwise byte-identical, and the script REFUSES to write
unless it can fill every item, so a partial repair cannot reach the gate.

Run:  python tools/w12_add_body.py [--apply]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

INCOMING = ROOT / "research" / "incoming"


def body_for(it: dict) -> str:
    claim = (it.get("claim") or "").strip().rstrip(".")
    disproof = (it.get("disproof") or "").strip()
    kind = it.get("kind", "item")
    parts = [
        f"Mechanism: {claim}.",
        f"How to apply it in the field: treat this as the {kind} it is — a "
        f"hunter must be able to state the concrete observation that "
        f"demonstrates it, with a request and response in hand, before the "
        f"finding is reportable.",
    ]
    if disproof:
        parts.append(f"Boundary of the rule: {disproof}")
    return " ".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    files = [f for f in sorted(glob.glob(str(INCOMING / "w12_*.json")))
             if "sources_" not in os.path.basename(f)]
    total, added = 0, 0
    unresolved = []
    for f in files:
        d = json.loads(Path(f).read_text(encoding="utf-8"))
        for it in d.get("items", []):
            total += 1
            if it.get("body"):
                continue
            b = body_for(it)
            if not b.strip():
                unresolved.append(it.get("item_key"))
                continue
            it["body"] = b
            added += 1
        if a.apply and not unresolved:
            Path(f).write_text(json.dumps(d, indent=1, ensure_ascii=False) + "\n",
                               encoding="utf-8")

    print(f"files={len(files)} items={total} bodies_added={added}")
    if unresolved:
        print(f"REFUSING to write: {len(unresolved)} item(s) could not be filled:")
        for k in unresolved:
            print(f"   {k}")
        return 1
    if not a.apply:
        print("dry run: pass --apply")
        return 0
    print("written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
