"""Skill generation (brief §6.F, §18).

Generates one INDEPENDENT, self-contained skill per bug class, with version
history. Skills are projections of the database: regenerate, never hand-edit.

A generated skill is deliberately thin. It carries only what a hunter needs to
start and what would make them stop — prerequisites, signals, techniques, the
validation bar, and the false-positive rules. It does not restate the whole
class document; under the merged tree that is the bundle's own
EVIDENCE.md, and the skill links to it there.

Version history (brief §18: "every meaningful skill change should preserve
version history or a recoverable diff"):
    skills/<id>/SKILL.md
    skills/<id>/HISTORY.md          append-only, with the metric delta that
                                    justified the change
A skill is only rewritten when the regenerated content differs from the current
file, so an unchanged class produces no spurious version bump.
"""
from __future__ import annotations

import difflib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import config, quality, store

VERSION = "1.0.0"

_HEADER = """---
name: {id}-hunting
description: Use when hunting {name} in a {surface} target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# {name} — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `{surface}` · CWE {cwe} · OWASP {owasp}
> evidence: {n_items} items, {n_supported} supported, {n_fp} FP rules, {n_chains} chains
> maturity: **{state}**{missing}
"""

_ORDER = ["prerequisite", "signal", "technique", "test", "validation",
          "fp_rule", "evidence", "impact", "variant", "bypass", "chain_link"]
_TITLE = {
    "prerequisite": "Prerequisites (do not start without these)",
    "signal": "Recon signals (where to look)",
    "technique": "Techniques (what to change)",
    "test": "Tests",
    "validation": "Validation bar (how to prove it)",
    "fp_rule": "False-positive rules (when to reject it)",
    "evidence": "Evidence requirements",
    "impact": "Impact framing",
    "variant": "Variants",
    "bypass": "Defence bypasses",
    "chain_link": "Chaining opportunities",
}


def render(con: sqlite3.Connection, class_id: str) -> str:
    from .retrieval import class_digest
    d = class_digest(con, class_id)
    m = d["maturity"]
    missing = (f" — missing: {', '.join(m['missing'])}" if m["missing"] else "")
    out = [_HEADER.format(
        id=class_id, name=d["name"], surface=d["surface"], cwe=d["cwe"] or "—",
        owasp=d["owasp"] or "—", n_items=m["n_items"], n_supported=m["n_supported"],
        n_fp=m["n_fp"], n_chains=m["n_chains"], state=m["state"], missing=missing,
    )]
    if d["summary"]:
        out.append(d["summary"] + "\n")
    if d["aliases"]:
        out.append("**Also called:** " + ", ".join(d["aliases"]) + "\n")

    for kind in _ORDER:
        items = d["by_kind"].get(kind)
        if not items:
            continue
        out.append(f"\n## {_TITLE[kind]}\n")
        # Sorted by item_key, not by score: scores tie, and a non-deterministic
        # tie-break makes every regeneration differ, which produces a spurious
        # HISTORY.md version bump each run and destroys the signal that a
        # version bump is supposed to carry.
        for it in sorted(items, key=lambda x: x["item_key"]):
            mark = {"high_confidence": "", "supported": "", "under_review": " _(unverified)_",
                    "discovered": " _(unverified)_"}.get(it["state"], " _(unverified)_")
            out.append(f"- {it['claim']}{mark}")
            if it.get("disproof"):
                out.append(f"  - **Disproof:** {it['disproof']}")
            srcs = it.get("sources") or []
            if srcs:
                out.append("  - Sources: " +
                           " · ".join(f"<{u}>" for u in srcs[:3]))

    if d["false_positives"]:
        out.append("\n## Rejected before you report\n")
        for f in d["false_positives"]:
            out.append(f"- **{f['hypothesis']}**")
            out.append(f"  - Killed by: {f['invalidated_by']}")
            out.append(f"  - Rule: {f['rejection_rule']}")

    if d["related_classes"]:
        out.append("\n## Chains to\n")
        out += [f"- `{r['class_id']}` ({r['chains']} shared chain(s))"
                for r in d["related_classes"]]

    # MERGED TREE: the class document is the bundle's own EVIDENCE.md, and its
    # path depends on the domain the db assigns this class to. Hardcoding
    # `classes/<id>.md` here produced one dead reference per skill -- 62 of them.
    from wks import domains as _doms
    _con = store.open_db()
    try:
        _rel = _doms.class_dir(class_id, _con).relative_to(config.root())
        _rel_s = _rel.as_posix() + "/knowledge/DIGEST.md"
    except KeyError:
        # Unmapped class. The fallback used to be `skills/<id>/EVIDENCE.md`,
        # which is doubly wrong now: the flat skills root is retired AND no
        # writer has ever produced an EVIDENCE.md, so the link pointed at a
        # file that did not exist. It now names the class's own directory, and
        # says plainly that the digest is absent rather than linking into a
        # void — a dangling link is worse than a stated gap.
        _rel_s = (f"{_doms.domains_root().relative_to(config.root()).as_posix()}"
                  f"/_unmapped/{class_id} (no digest generated yet)")
    finally:
        _con.close()
    out.append(f"\n---\nFull class document: `{_rel_s}` · "
               f"retrieve more with `python -m wks.cli search \"<query>\" "
               f"--class-id {class_id}`\n")
    return "\n".join(out)


def write_skill(con: sqlite3.Connection, class_id: str) -> dict:
    """Render the hunting skill into the class's own `skills/` directory.

    A skill belongs to the bug class it hunts, so it lives inside that class
    rather than in a flat root: `domains/web/xss/skills/SKILL.md`. Resolved via
    wks.domains so this writer and the taxonomy generator cannot disagree.
    """
    from . import domains as _domains
    out_dir = _domains.class_subdir(class_id, "skills", con)
    out_dir.mkdir(parents=True, exist_ok=True)
    skill = out_dir / "SKILL.md"

    # Record skill_path BEFORE rendering. maturity() reports `skill` as missing
    # while skill_path is NULL, so rendering first and persisting after makes
    # every regeneration differ by one line and manufactures a version bump on
    # every run — the history would fill with no-op "changes".
    row = store.get_class(con, class_id)
    store.upsert_class(con, class_id, row["name"], row["surface"],
                       status=row["status"], skill_path=str(skill))
    con.commit()

    content = render(con, class_id)

    if skill.exists():
        current = skill.read_text(encoding="utf-8")
        if current == content:
            return {"class_id": class_id, "changed": False}
        diff = list(difflib.unified_diff(
            current.splitlines(), content.splitlines(),
            fromfile=f"{class_id}@current", tofile=f"{class_id}@new", lineterm=""))
    else:
        diff = [f"(initial generation, {datetime.now(timezone.utc):%Y-%m-%d})"]

    skill.write_text(content, encoding="utf-8")

    m = quality.maturity(con, class_id)
    hist = out_dir / "HISTORY.md"
    if not hist.exists():
        hist.write_text(
            "# History\n\nAppend-only. Each entry records WHY the skill changed, "
            "not just that it did. Improvement means better hunting behaviour, "
            "not more text.\n", encoding="utf-8")
    with hist.open("a", encoding="utf-8") as fh:
        fh.write(
            f"\n## {datetime.now(timezone.utc):%Y-%m-%d %H:%M} — {len(diff)} diff lines\n"
            f"- items: {m['n_items']} (supported {m['n_supported']}), "
            f"FP rules {m['n_fp']}, chains {m['n_chains']}, "
            f"state {m['state']}\n")
        if m["missing"]:
            fh.write(f"- still missing: {', '.join(m['missing'])}\n")
        fh.write("\n```diff\n" + "\n".join(diff[:120]) +
                 ("\n... (truncated)" if len(diff) > 120 else "") + "\n```\n")

    store.upsert_class(con, class_id, store.get_class(con, class_id)["name"],
                       store.get_class(con, class_id)["surface"],
                       skill_path=str(skill))
    con.commit()
    return {"class_id": class_id, "changed": True, "diff_lines": len(diff)}


def generate_all(con: sqlite3.Connection) -> list[dict]:
    results = []
    for row in con.execute("SELECT id FROM bug_class ORDER BY id").fetchall():
        m = quality.maturity(con, row["id"])
        if m["n_items"] == 0:
            continue  # a skill with no knowledge is worse than no skill
        results.append(write_skill(con, row["id"]))
    return results


def main() -> int:
    con = store.open_db(create=True)
    res = generate_all(con)
    for r in res:
        print(f"  {r['class_id']:16} {'UPDATED' if r['changed'] else 'unchanged'}"
              + (f" ({r['diff_lines']} diff lines)" if r["changed"] else ""))
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
