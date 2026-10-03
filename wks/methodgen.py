"""Derive an actionable hunting procedure from verified items.

    python -m wks.methodgen [--class idor ...] [--apply]

Why this exists
---------------
The spec asks for a Methodology Agent that converts knowledge into a hunting
procedure: preconditions, reconnaissance signals, test sequence, validation,
false-positive rejection, evidence, chaining. Every other module stores or
gates knowledge. None of them produced the thing a hunter actually reads at
2am with a target open.

Writing that procedure by hand is how methodology files rot: they drift from
the evidence, and nobody notices for months. So this derives it from the
verified items, in a fixed order, and only for item kinds that are present.
A class with no validation items gets a section that says so, rather than a
plausible-sounding one that nobody wrote.

The output is a projection, like SKILL.md: regenerated from the database, never
hand-edited. That is what makes it trustworthy — it cannot claim coverage the
evidence does not support.

Kind ordering is the whole design. A procedure that starts with techniques is
useless, because a technique is only reachable once you know the precondition
holds and have identified the surface. Hence: prerequisite -> signal ->
technique -> validation -> fp_rule -> bypass -> chain_link -> impact.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import config, store  # noqa: E402

# Order is the hunting order. Each stage depends on the one before it.
STAGES = [
    ("prerequisite", "Preconditions",
     "Nothing below is reachable until these hold. Confirm each against the "
     "target before spending time on the technique."),
    ("signal", "Reconnaissance signals",
     "What to look for while mapping the surface, and where each signal "
     "tells you the rest of the procedure is worth running."),
    ("technique", "Test sequence",
     "Concrete mutations to try. Each is written to be executable, not to be "
     "a description of the vulnerability."),
    ("validation", "Validation",
     "How to prove the finding rather than infer it. A technique that cannot "
     "be validated must not be reported."),
    ("fp_rule", "False-positive rejection",
     "The checks that eliminate the most common non-findings. Run these "
     "BEFORE reporting, not after a rejection."),
    ("bypass", "Known bypasses",
     "Filters and controls that have defeated the techniques above. Treat "
     "these as the reason a naive test fails, not as proof of safety."),
    ("chain_link", "Chaining",
     "How this class escalates when combined with others. Each step is "
     "anchored to a promoted item."),
    ("impact", "Impact",
     "What is actually demonstrable, and what to stop claiming."),
]

MISSING = ("_No verified {kind} items yet._ Derived from evidence only, so "
           "this section is empty rather than plausible.\n")


def _sources(con, item_id: int) -> list[dict]:
    """Sources linked to an item, via the item_source link table.

    Kept here rather than calling a helper because no such helper existed —
    every module was doing this join inline. Two sources on the same host are
    collapsed by `dict.fromkeys`, so the rendered evidence line cannot imply
    more publisher diversity than the item actually has.
    """
    rows = con.execute(
        """SELECT s.host, s.url FROM item_source x
           JOIN source s ON s.id = x.source_id
           WHERE x.item_id = ? ORDER BY s.host""", (item_id,)).fetchall()
    seen, out = set(), []
    for r in rows:
        if r["host"] in seen:
            continue
        seen.add(r["host"])
        out.append({"host": r["host"], "url": r["url"]})
    return out


def _items_by_kind(con, class_id: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    # The `EXISTS item_source` guard is what makes this honest: an item with no
    # linked source row has no evidence behind it, so it must not appear in a
    # procedure that claims to be evidence-derived. The hard gates in
    # quality.py already prevent promotion of such items, but this projection
    # must not depend on that staying true.
    rows = con.execute(
        """SELECT i.id, i.item_key, i.kind, i.claim, i.body, i.disproof,
                  q.validation_state, q.score
           FROM item i JOIN quality q ON q.item_id = i.id
           WHERE i.class_id = ? AND i.status='active'
             AND q.validation_state IN ('supported','high_confidence')
             AND EXISTS (SELECT 1 FROM item_source x WHERE x.item_id = i.id)
           GROUP BY i.id
           ORDER BY q.score DESC, i.item_key""",
        (class_id,)).fetchall()
    for r in rows:
        srcs = _sources(con, int(r["id"]))
        out.setdefault(r["kind"], []).append(
            {"item_key": r["item_key"], "claim": r["claim"],
             "body": r["body"], "disproof": r["disproof"],
             "state": r["validation_state"], "sources": srcs})
    return out


def render(con, class_id: str) -> str:
    cls = con.execute(
        "SELECT name, surface, cwe, owasp, summary FROM bug_class WHERE id=?",
        (class_id,)).fetchone()
    by_kind = _items_by_kind(con, class_id)
    total = sum(len(v) for v in by_kind.values())

    L = [f"# Methodology — {cls['name'] if cls else class_id}", ""]
    L.append(f"> Derived from {total} verified items. Regenerate with "
             "`python -m wks.methodgen --class {0} --apply`. Do not hand-edit: "
             "this file is a projection of the evidence, and edits are lost "
             "on the next cycle.".format(class_id))
    L.append("")
    if cls and cls["summary"]:
        L += [f"**Surface.** {cls['summary']}", ""]
    if cls and (cls["cwe"] or cls["owasp"]):
        cwe = (cls["cwe"] or "").strip()
        if cwe and not cwe.upper().startswith("CWE"):
            cwe = "CWE-" + cwe          # taxonomy stores it bare in some seeds
        bits = " · ".join(filter(None, [cwe, cls["owasp"] or ""]))
        if bits:
            L += [f"**References.** {bits}", ""]

    step = 0
    for kind, heading, why in STAGES:
        rows = by_kind.get(kind, [])
        if not rows:
            L += [f"## {heading}", "", MISSING.format(kind=kind), ""]
            continue
        step += 1
        L += [f"## {step}. {heading}", "", f"_{why}_", ""]
        for r in rows:
            L.append(f"**{r['claim']}**")
            L.append("")
            L.append(r["body"].strip())
            L.append("")
            if r["disproof"]:
                L.append(f"- *Disproof:* {r['disproof'].strip()}")
            if r["sources"]:
                refs = "; ".join(
                    f"[{s['host']}]({s['url']})" for s in r["sources"][:3])
                L.append(f"- *Evidence:* {r['state']} — {refs}")
            L.append("")

    missing = [h for k, h, _ in STAGES if not by_kind.get(k)]
    if missing:
        L += ["## Coverage gap", "",
              "These stages have no verified evidence and are therefore "
              "absent above: " + ", ".join(missing) + ".",
              "A procedure with a missing validation stage is not safe to "
              "act on — it produces findings rather than proofs.", ""]

    L += ["---", "",
          "*Generated from the evidence base. Where this file and the "
          "database disagree, the database is correct.*", ""]
    return "\n".join(L)


def generate_all(con) -> dict:
    """Regenerate every class methodology. Entry point used by the cycle.

    Each class's derived competency view is written into that class's own
    `assessment/` directory. It is an ASSESSMENT artifact — what this class's
    evidence actually covers — not shared methodology, so it is colocated with
    the class it measures rather than pooled in a global `derived/` folder
    where 63 files with no visible owner compete for the same directory.
    """
    from . import domains as _domains
    written = 0
    ids = [r["id"] for r in con.execute(
        "SELECT id FROM bug_class WHERE status!='retired' ORDER BY id")]
    for cid in ids:
        text = render(con, cid)
        outdir = _domains.class_subdir(cid, "assessment", con)
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / "COMPETENCY.md"
        if path.exists() and path.read_text(encoding="utf-8") == text:
            continue          # unchanged: never bump last_reviewed for nothing
        path.write_text(text, encoding="utf-8")
        # Repo-relative, never absolute. An absolute path here bakes one
        # user's home directory into the canonical db, so the tree cannot be
        # relocated or checked on another host -- measured: all 15 rows held a
        # user-home prefix, reported NON-PORTABLE by
        # check_methodology_coverage.py. Resolution happens at read time via
        # config.root(), which already supports HERMES_CYBER_ROOT.
        con.execute("UPDATE bug_class SET methodology=?, last_reviewed=? "
                    "WHERE id=?",
                    (f"{_domains.class_rel(cid, con)}/assessment/COMPETENCY.md",
                     store.now(), cid))
        written += 1
    if written:
        con.commit()
    return {"written": written, "classes": len(ids)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wks.methodgen")
    ap.add_argument("--class", dest="classes", action="append", default=None)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    root = config.root()
    con = store.open_db(create=False)
    ids = args.classes or [
        r["id"] for r in con.execute(
            "SELECT id FROM bug_class WHERE status!='retired' ORDER BY id")]

    from . import domains as _domains
    written = changed = 0
    for cid in ids:
        text = render(con, cid)
        # Same owner as generate_all(). This used to write a flat
        # `methodology/derived/<id>.md` and record that path in the db, which
        # meant the CLI and the cycle wrote the SAME artifact to TWO locations
        # — the duplicate-owner defect the reorg skill warns about, and it
        # would have recreated the retired `methodology/` root on the next
        # `python -m wks.methodgen --apply`.
        outdir = _domains.class_subdir(cid, "assessment", con)
        path = outdir / "COMPETENCY.md"
        if not args.apply:
            print(f"{cid:16} {len(text):6} chars  -> {path}  (dry run)")
            continue
        outdir.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_text(encoding="utf-8") == text:
            continue  # unchanged: no spurious history bump
        path.write_text(text, encoding="utf-8")
        con.execute("UPDATE bug_class SET methodology=?, last_reviewed=? "
                    "WHERE id=?",
                    (f"{_domains.class_rel(cid, con)}/assessment/COMPETENCY.md",
                     store.now(), cid))
        changed += 1
        written += 1
    if args.apply:
        con.commit()
        print(f"wrote {written} methodology files ({changed} changed)")
    else:
        print(f"\n{len(ids)} classes would be rendered. Pass --apply to write.")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())