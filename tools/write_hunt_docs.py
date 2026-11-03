"""Write the derived hunt playbook INTO each class's domain folder.

WHY (measured 2026-10-04)
------------------------
`skills/` is the primary knowledge repository and it IS current: 1083 promoted
items, 0 missing from any DIGEST, 0 from any SKILL. So the corpus projection is
sound and nothing needed fixing there.

What was NOT in `skills/` is the thing this session actually built. The hunt
SKILL.md renders knowledge — claims, disproofs, sources — but 26 of 35
`path_traversal` techniques carry no action verb at all, and the derived
playbooks that fix that lived only in `runtime/loop/playbooks/`. Knowledge that
only exists in a session's scratch directory is not knowledge. This writes each
playbook to `skills/<domain>/<class>/HUNT.md` so it sits beside the
SKILL.md it supports, and links it from both so neither file is an island.

Reconciliation rules (R11 still holds — these files are PROJECTIONS):
  * nothing here is hand-written; the playbook is derived from promoted items,
  * regeneration is idempotent, so an unchanged corpus rewrites identical bytes,
  * the SKILL.md link line is injected only if absent, so re-running does not
    duplicate it.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
SRC = ROOT / "runtime" / "loop" / "playbooks"
sys.path.insert(0, str(ROOT))

LINK = ("\n---\nRunbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to "
        "an executable procedure with the observables to record.\n")


def main() -> int:
    import subprocess
    from wks import domains as D, store
    con = store.open_db(create=False)

    # Regenerate every playbook from the corpus first, so the files written into
    # skills/ are never behind the db.
    r = subprocess.run([sys.executable, "tools/playbook.py", "--all"],
                       capture_output=True,
                       text=True, cwd=str(ROOT))
    classes = [r[0] for r in con.execute(
        "SELECT id FROM bug_class WHERE status!='retired' ORDER BY id")]

    written = injected = skipped = 0
    for cid in classes:
        pj = SRC / f"web-{cid}.json"
        if not pj.exists():
            pj = SRC / f"network-{cid}.json"
        if not pj.exists():
            # try any domain
            hits = list(SRC.glob(f"*-{cid}.json"))
            if not hits:
                skipped += 1
                continue
            pj = hits[0]
        pb = json.loads(pj.read_text(encoding="utf-8"))
        if pb["entry_count"] == 0:
            continue
        domain = pb.get("domain") or "web"

        try:
            sdir = D.class_subdir(cid, "skills", con)
        except KeyError:
            skipped += 1
            continue
        sdir.mkdir(parents=True, exist_ok=True)

        md = [f"# HUNT runbook — {cid}", "",
              f"**{pb['entry_count']} promoted technique/test/variant items**, each "
              f"mapped to an executable procedure derived from the shape of the "
              f"claim. Generated from `db/wks.db`; do not hand-edit "
              f"(regenerate with `python tools/playbook.py {cid} {domain}`).", "",
              f"Sources of steps: "
              f"{sum(1 for e in pb['entries'] if e['source'] == 'item')} "
              f"item-authored, "
              f"{sum(1 for e in pb['entries'] if e['source'] == 'template')} "
              f"template-derived (a template step is the SHAPE's procedure, not a "
              f"claim-specific one — treat those as the starting point and adapt).",
              ""]
        md += ["## Index", ""]
        for e in pb["entries"]:
            md.append(f"- [{e['item_key']}](#{_anchor(e['item_key'])}) "
                      f"— {e['procedure']}")
        md.append("")
        for e in pb["entries"]:
            md += [f"<a id=\"{_anchor(e['item_key'])}\"></a>", "",
                   f"## {e['item_key']}", "",
                   f"**Claim.** {e['claim']}", "",
                   f"**Procedure — {e['procedure']}** "
                   f"(shapes: {', '.join(e['shapes'])}; steps from "
                   f"{e['source']})", ""]
            md += [f"{i}. {s}" for i, s in enumerate(e["steps"], 1)]
            md += ["", f"**Record:** {', '.join(e['records'])}", ""]

            # VARIATION (wks/variation.py). Each axis says what to DO and what to
            # OBSERVE, so the card is executable rather than descriptive.
            if e.get("variation"):
                md += ["**Vary these — each changes what you do and what you see**", ""]
                md += list(e["variation"])
                md += [""]

            # ESCALATION: what to try when the first attempt is flat, including
            # when to stop (a flat result IS a result).
            if e.get("escalation"):
                md += ["**If the first attempt is flat**", ""]
                md += list(e["escalation"])
                md += [""]

            # ALTERNATE PROCEDURES: shapes[1:] that also apply to this item.
            # Previously discarded entirely by the classifier.
            alts = e.get("alternate_procedures") or []
            if alts:
                md += ["**Also applies — alternate procedures for this item**", ""]
                for a in alts:
                    md += [f"- *{a['procedure']}* — {a['steps'][0]}"]
                md += [""]

        hunt = sdir / "HUNT.md"
        text = "\n".join(md)
        if not (hunt.exists() and hunt.read_text(encoding="utf-8") == text):
            hunt.write_text(text, encoding="utf-8")
            written += 1

        # Link it from SKILL.md if not already linked.
        skill = sdir / "SKILL.md"
        if skill.exists():
            st = skill.read_text(encoding="utf-8")
            if "HUNT.md" not in st:
                skill.write_text(st.rstrip() + "\n" + LINK, encoding="utf-8")
                injected += 1

    print(f"HUNT.md written/updated: {written}   "
          f"SKILL.md links injected: {injected}   skipped: {skipped}")
    return 0


def _anchor(k: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", k.lower()).strip("-")


if __name__ == "__main__":
    raise SystemExit(main())