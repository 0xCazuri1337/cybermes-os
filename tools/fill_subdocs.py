#!/usr/bin/env python
"""Fill the bug-class sub-documents from the GATED corpus.

    python tools/fill_subdocs.py            # dry run, writes nothing
    python tools/fill_subdocs.py --apply

Why this exists. `bug-classes/web/xss/*.md` were empty templates (15 sections
each, all reading "Not yet researched") while `classes/xss.md` had 48 verified
items. The README promises that directory is the routing surface, so a hunter
following it found nothing.

Two rules make this safe to automate:

  1. EVERY sentence traceable to an item that passed the gate. Nothing is
     invented here — this file selects and groups, it does not author.
  2. Items that do not fit a sub-document are reported, not silently dropped.
     A gap that is visible beats a doc that looks complete and isn't.

Sub-doc routing is by MECHANISM (what has to be true for it to fire), because
that is what determines the probe. Routing by label is what produced six empty
files in the first place.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import config, store  # noqa: E402

ROOT = config.root()
# MERGED TREE (2026-10-02): the XSS sub-documents live inside the xss
# bundle, in topics/. Derived from the db split, not hardcoded.
import sys as _sys
_sys.path.insert(0, str(ROOT))
from wks import config as _cfg, domains as _doms
from wks import store as _store
_con = _store.open_db()
OUT = _doms.domain_dir(_doms.domain_of(_con, "xss")) / "xss" / "topics"
_con.close()

# (target file, [(item_key_substring, human label), ...])
# An item lands in a sub-doc when its key contains one of the substrings.
ROUTES: dict[str, list[tuple[str, str]]] = {
    "reflected-xss.md": [
        ("reflected", "reflected"),
        ("prereq.reflected", "reflected"),
        ("evidence.attr_context", "attribute-context breakout"),
        # Entry-point discovery, context determination and execution proof are
        # the three steps every hunt performs first regardless of delivery
        # type, so they route here as well as appearing cross-cutting.
        ("test.entrypoints", "marker sweep"),
        ("test.context", "context determination"),
        ("test.execution", "execution confirmation"),
    ],
    "stored-xss.md": [
        ("stored", "stored"),
        ("prereq.stored", "stored"),
        ("test.stored", "two-identity testing"),
    ],
    "dom-xss.md": [
        ("technique.dom", "DOM sink"),
        ("signal.dom", "DOM source"),
        ("validation.dom", "DOM validation"),
        ("technique.client_side_template_injection", "client-side template injection"),
        ("technique.postmessage", "postMessage"),
        ("dangling", "dangling markup"),
        ("evidence.dom_sink", "innerHTML vs document.write"),
        ("evidence.csti", "client-side template injection"),
        ("evidence.prototype_pollution", "prototype pollution to script src"),
        ("evidence.postmessage", "postMessage origin handling"),
        ("evidence.trusted_types", "Trusted Types"),
        ("test.dom", "DOM sink testing"),
        ("test.bypass", "filter-bypass probe sequence"),
    ],
    "mutation-xss.md": [
        ("innerhtml_rejects_script", "innerHTML vs document.write"),
        ("js_script_tag.html_parsed_before_js", "HTML parsed before JS"),
        ("evidence.dom_sink", "innerHTML vs document.write"),
    ],
    "framework-xss.md": [
        ("template_literal", "template literal"),
        ("html_attribute", "attribute context"),
        ("js_string", "JS string context"),
        ("html_between_tags", "between tags"),
        # Evidence items that demonstrate a framework/template mechanism in practice.
        ("evidence.csti", "client-side template injection"),
        ("evidence.attr_context", "attribute-context breakout"),
    ],
    "blind-xss.md": [
        ("dangling", "content capture without script"),
        ("samesite", "cookie posture"),
        ("evidence.dangling_markup", "content capture without script"),
    ],
}

# `test` items whose topic is not tied to one delivery type, and the control
# checks that gate any impact claim regardless of how the script was reached.
TEST_CROSSCUT = ("test.controls.",)

# Cross-cutting items apply to EVERY sub-document. Duplicating them into each
# file would be accurate but would also mean 6 copies to drift out of sync, so
# they are listed once per file under a single heading with a pointer back to
# the canonical copy. An item is cross-cutting when its key says so.
CROSSCUTTING = ("fp_rule.", "chain_link.", "validation.httponly",
                "validation.encoding", "validation.self_fired",
                "bypass.csp_", "bypass.trusted_types",
                # Filter evasion is not tied to a delivery type — it applies
                # wherever the payload reaches a context. Forcing it into one
                # sub-doc would be wrong, so it is cross-cutting.
                "bypass.filter.",
                # CSP bypass is not tied to a delivery type either: a policy
                # that can be overwritten breaks any context that executes script.
                "evidence.csp.",
                "technique.json_response", "impact.transport_security")


def is_crosscut(key: str) -> bool:
    return any(t in key for t in CROSSCUTTING) or any(t in key for t in TEST_CROSSCUT)


HEAD = """# {title}

> GENERATED by `tools/fill_subdocs.py` from gated corpus items in `db/wks.db`.
> Every bullet below traces to an item that passed the evidence gate
> (>= 2 distinct publisher hosts, quote verified against the live page).
> Re-run after new research: `python tools/fill_subdocs.py --apply`

{summary}

"""

SECTIONS = [
    # NOTE: the corpus kind is `prerequisite`, not `prereq`. The two differed,
    # so every prerequisite item was selected by the router and then silently
    # dropped by this loop — the file looked complete and was missing its
    # "How it works" section. Kind strings must match VALID_KINDS exactly.
    ("How it works", "prerequisite"),
    ("Where to look", "signal"),
    ("Technique", "technique"),
    ("Test", "test"),
    ("Validation bar", "validation"),
    ("Reject before you report", "fp_rule"),
    ("Evidence", "evidence"),
    ("Impact", "impact"),
    ("Variant", "variant"),
    ("Bypass", "bypass"),
    ("Chaining", "chain_link"),
]

SECTION_NOTE = {
    "fp_rule": "Each bullet is a rejection rule — the observation that KILLS the candidate.",
    "validation": "Each bullet states what must be true before this is a finding.",
    "chain_link": "Each bullet is a step in escalating script execution into impact.",
}


def load(con: sqlite3.Connection, class_id: str) -> list[dict]:
    rows = con.execute(
        """SELECT i.item_key, i.kind, i.claim, i.body, i.disproof
           FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.class_id=? AND i.status='active'
             AND q.validation_state IN ('supported','high_confidence')
           ORDER BY i.kind, i.item_key""",
        (class_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def hosts(con: sqlite3.Connection, item_id: int) -> list[str]:
    return sorted({e["host"] for e in store.item_evidence(con, item_id)})


def render(items: list[dict], cross: list[dict], title: str, summary: str) -> str:
    out = [HEAD.format(title=title, summary=summary)]
    for heading, kind in SECTIONS:
        picked = [it for it in items if it["kind"] == kind]
        if not picked:
            continue
        out.append(f"## {heading}\n")
        if kind in SECTION_NOTE:
            out.append(f"_{SECTION_NOTE[kind]}_\n")
        for it in picked:
            out.append(f"- **{it['claim']}**")
            out.append(f"  - kills it if: {it['disproof']}")
            out.append(f"  - `{it['item_key']}`")
        out.append("")

    # `cross` arrives from the caller: it is the class-wide cross-cutting set,
    # NOT a subset of `items`. Recomputing it here from the routed slice is what
    # made the section vanish from every file whose routed set held only
    # techniques.
    if cross:
        out.append("## Applies to every XSS sub-type\n")
        out.append("_False-positive rules, validation bars and escalation steps that are not "
                   "specific to this delivery type. Canonical copies live in "
                   "`skills/web/xss/CLASS.md` and "
                   "`skills/web/xss/SKILL.md`; they are listed here so this "
                   "file can be used on its own._\n")
        for it in cross:
            out.append(f"- **{it['claim']}**")
            out.append(f"  - kills it if: {it['disproof']}")
            out.append(f"  - `{it['item_key']}`")
        out.append("")

    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    # The merged layout puts these pages in a `topics/` dir that does not exist
    # until something creates it; a bare write raised FileNotFoundError and the
    # generator wrote nothing at all.
    OUT.mkdir(parents=True, exist_ok=True)
    ap = argparse.ArgumentParser(prog="fill_subdocs.py")
    ap.add_argument("--apply", action="store_true", help="write files (default: dry run)")
    ap.add_argument("--class", dest="class_id", default="xss")
    args = ap.parse_args(argv)

    con = store.open_db(create=False)
    all_items = load(con, args.class_id)
    print(f"{len(all_items)} gated items for class {args.class_id!r}\n")

    # Cross-cutting set is computed ONCE from the whole class and passed to
    # every render() call, so "applies to every sub-type" is literally true.
    cross_all = [it for it in all_items if is_crosscut(it["item_key"])]

    routed: set[str] = set()
    for fname, rules in ROUTES.items():
        keys = [k for k, _ in rules]
        sel = [it for it in all_items if any(k in it["item_key"] for k in keys)]
        for it in sel:
            routed.add(it["item_key"])
        if not sel:
            print(f"  {fname:22} NO MATCH — left as-is")
            continue
        title = fname.replace("-", " ").replace(".md", "").title()
        summary = (f"{len(sel)} of {len(all_items)} gated XSS items route here, selected "
                   f"by mechanism rather than by label.")
        body = render(sel, cross_all, f"XSS — {title}", summary)
        path = OUT / fname
        cur = path.read_text(encoding="utf-8") if path.exists() else ""
        stubs = cur.count("Not yet researched")
        action = "UPDATE" if (args.apply and body != cur) else ("WOULD UPDATE" if body != cur else "unchanged")
        print(f"  {fname:22} {len(sel):>2} items, {stubs:>2} stubs -> {action}")
        if args.apply and body != cur:
            path.write_text(body, encoding="utf-8")

    cross = [it for it in all_items if is_crosscut(it["item_key"])]
    routed.update(it["item_key"] for it in cross)
    orphan = [it["item_key"] for it in all_items
          if it["item_key"] not in routed and not is_crosscut(it["item_key"])]
    print(f"\nrouted {len(routed)}/{len(all_items)} directly, "
          f"{len(cross)} cross-cutting (listed in every file)")
    if orphan:
        print(f"\nNOT routed to any sub-document ({len(orphan)}):")
        for k in orphan:
            print("   ", k)
        print("These live in skills/web/xss/CLASS.md and "
              "skills/web/xss/SKILL.md only.")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())