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

from . import config, hunt_playbook, quality, store

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
            # Exact-duplicate claims are collapsed before rendering. Measured
            # 2026-10-04: 121 (class, claim) groups held more than one active row,
            # untracked by dedup_of/canonical_id, so the same line was rendered
            # twice -- once `_(unverified)_` and once not. That inflated apparent
            # breadth and made the promoted state look ambiguous.
            items = hunt_playbook.dedupe_items(items)
            # Sorted by claim, not by score: scores tie, and a non-deterministic
            # tie-break makes every regeneration differ, which produces a spurious
            # HISTORY.md version bump each run and destroys the signal that a
            # version bump is supposed to carry.
            for it in sorted(items, key=lambda x: x["claim"]):
                mark = {"high_confidence": "", "supported": "", "under_review": " _(unverified)_",
                        "discovered": " _(unverified)_"}.get(it["state"], " _(unverified)_")
                claim = it["claim"]
                if it.get("_n_collapsed"):
                    claim += f"  _(merged {it['_n_collapsed']} duplicate row(s))_"
                out.append(f"- {claim}{mark}")
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
    # SIBLING ARTIFACTS (added 2026-10-04). MEASURED: the HUNT runbook and the
    # refuted-claims record were linked by APPENDING to SKILL.md after
    # generation, and `skills-sync --apply` then regenerated the file and
    # stripped both links silently. The projection is authoritative (R11), so a
    # hand-appended link can never survive — the links must be emitted BY the
    # generator, and only when the target actually exists so a dangling link is
    # impossible. Paths are resolved HERE because `_con` is closed in `finally`.
    _skill_dir = None
    _refuted = None
    try:
        _rel = _doms.class_dir(class_id, _con).relative_to(config.root())
        _rel_s = _rel.as_posix() + "/knowledge/DIGEST.md"
        _skill_dir = _doms.class_subdir(class_id, "skills", _con)
        _refuted = _skill_dir.parent / "knowledge" / "refuted-claims.md"
    except KeyError:
        # Unmapped class. The fallback used to be `skills/<id>/EVIDENCE.md`,
        # which is doubly wrong now: the flat skills root is retired AND no
        # writer has ever produced an EVIDENCE.md, so the link pointed into a
        # void. It now names the class's own directory and states plainly that
        # the digest is absent — a dangling link is worse than a stated gap.
        _rel_s = (f"{_doms.domains_root().relative_to(config.root()).as_posix()}"
                  f"/_unmapped/{class_id} (no digest generated yet)")
    finally:
        _con.close()
    out.append(f"\n---\nFull class document: `{_rel_s}` · "
               f"retrieve more with `python -m wks.cli search \"<query>\" "
               f"--class-id {class_id}`\n")

    # Emitted only when the target exists, so a dangling link is impossible.
    _extra = []
    try:
        if (_skill_dir / "HUNT.md").exists():
            _extra.append(
                "Runbook: [`HUNT.md`](HUNT.md) — every promoted technique "
                "mapped to an executable procedure with the observables to "
                "record.")
        if _refuted.exists():
            _extra.append(
                "Refuted/unverified claims: "
                "[`refuted-claims.md`](../knowledge/refuted-claims.md) — read "
                "before proposing a technique; claims here were examined and "
                "rejected, with the reasoning.")
    except NameError:
        pass          # routing failed above; no sibling links
    if _extra:
        out.append("---\n" + "\n".join(_extra) + "\n")

    # The hunt procedure is appended BEFORE the pointer block so the pointer
    # stays last. It is mechanics only: the ordered prerequisites, validation
    # bar and FP rules above remain the authority on whether a finding stands.
    body = "\n".join(out)
    return hunt_playbook.apply_to_rendered(body, d.get("surface") or "default", class_id)


def write_skill(con: sqlite3.Connection, class_id: str) -> dict:
    """Render the hunting skill into the class's own `skills/` directory.

    A skill belongs to the bug class it hunts, so it lives inside that class
    rather than in a flat root: `domains/web/xss/skills/SKILL.md`. Resolved via
    wks.domains so this writer and the taxonomy generator cannot disagree.
    """
    from . import domains as _domains
    # The output path comes from `config.root()` and the content comes from
    # `con`. If those two disagree, the write lands on the canonical tree
    # carrying a foreign corpus -- MEASURED 2026-10-31, see
    # wks.project.assert_canonical_connection.
    from .project import assert_canonical_connection
    assert_canonical_connection(con)
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


def _stalest_first(con: sqlite3.Connection, classes: list[str],
                   limit: int) -> list[str]:
    """The `limit` classes whose skill is most out of date.

    Staleness is the skill FILE's age on disk -- the artifact itself, not a
    bookkeeping column. `bug_class` has no `updated_at`, and the file's
    mtime is exactly what a reader of `domains/<...>/skills/SKILL.md` sees.
    A class whose skill file is missing is the stalest of all.
    """
    from . import domains as _domains

    def age(cid: str) -> float:
        try:
            out_dir = _domains.class_subdir(cid, "skills", con)
            p = out_dir / "SKILL.md"
            if not p.exists():
                return float("inf")
            return p.stat().st_mtime
        except Exception:
            return float("inf")

    return sorted(classes, key=age)[:limit]


def generate_all(con: sqlite3.Connection, *, limit: int | None = None
                 ) -> list[dict]:
    """Regenerate the skill for every class that has knowledge.

    `limit` bounds how many classes are processed, so an unattended cycle
    can cap its per-pass work.

    MEASURED 2026-10-31: this had no bound at all, and `wks.cycle.run_cycle`
    -- whose `max_items` parameter was never applied to anything -- called
    it for all 70 registered classes on every pass. The parameter existed
    on the CLI and did nothing, so the cycle's per-pass cost was whatever
    the corpus happened to be.

    When a limit is given, the classes processed are the ones whose skill
    is MOST out of date, not the first N by id: a bounded pass must still
    do the most useful work, and alphabetically-first classes are not
    necessarily the stale ones.
    """
    results = []
    classes = [r["id"] for r in
               con.execute("SELECT id FROM bug_class ORDER BY id").fetchall()]
    if limit is not None and limit >= 0:
        classes = _stalest_first(con, classes, limit)
    for cid in classes:
        m = quality.maturity(con, cid)
        if m["n_items"] == 0:
            continue  # a skill with no knowledge is worse than no skill
        results.append(write_skill(con, cid))
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
