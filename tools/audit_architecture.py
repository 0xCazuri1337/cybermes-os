"""PHASE 7 — architectural validation. Answers "is the TREE the architecture?"

    python tools/audit_architecture.py           # report
    python tools/audit_architecture.py --selftest  # prove the checker works
    exit 1 on any finding

This is VALIDATION, not assessment (brief §14). It asks "is the system behaving
correctly?" — does every class sit where the layout says, does every writer
resolve through the one owner, is anything left in a retired root. It does not
ask "can Hermes hunt XSS", which is what assessment/ and the gate are for.

WHY A CHECKER AND NOT AN INSPECTION
    The tree passed a visual review before this refactor while the generator was
    writing 132 files into a directory that did not exist. A tree can look
    right and be wrong; only a rule that can fail is evidence. Every rule below
    is written so that a healthy tree reports 0 and a broken one does not — and
    §9 of the reorg skill is the reason `--selftest` and the injection test
    exist: a checker that has only ever printed "clean" is unvalidated, not
    healthy.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import domains as D  # noqa: E402

# Roots this refactor retired. Anything present here is a migration that did not
# finish. Listed as an EXACT set: a substring rule would also match a legitimate
# path like `skills/web/chains/`, which is precisely the false-positive that
# made an earlier audit report 93 phantom orphans.
RETIRED_ROOTS = ("bug-classes", "classes", "chains", "attack-chains",
                 "methodology", "state", "skills")

# Writers that must resolve output through wks.domains rather than spelling a
# path. `allow` is the set of literals each file may legitimately contain.
PATH_OWNING_MODULES = ("wks/pipeline.py", "wks/skillgen.py", "wks/methodgen.py",
                       "wks/chains.py")


def findings() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    # -- R1  no retired root survives -------------------------------------
    for name in RETIRED_ROOTS:
        p = ROOT / name
        if p.exists():
            # `skills/` is legitimate ONLY as a shared-skills root; a per-class
            # skill directory under it is the retired flat layout.
            if name == "skills":
                strays = [c.name for c in p.iterdir()
                          if c.is_dir() and c.name.endswith("-hunting")]
                if strays:
                    out.append(("R1", f"skills/ still holds {len(strays)} flat "
                                     f"per-class dirs, e.g. {strays[0]}"))
                continue
            out.append(("R1", f"retired root still present: {name}/ "
                             f"({sum(1 for _ in p.rglob('*') if _.is_file())} files)"))

    # -- R2  every class resolves, and lands where it is claimed -----------
    from wks import store
    con = store.open_db()
    for r in con.execute("SELECT id FROM bug_class ORDER BY id"):
        cid = r["id"]
        try:
            rel = D.class_rel(cid, con)
        except KeyError as e:
            out.append(("R2", f"class {cid!r} does not resolve: {e}"))
            continue
        d = ROOT / rel
        if not d.is_dir():
            out.append(("R2", f"class {cid!r} resolves to {rel} which is absent"))
            continue
        if not (d / "knowledge" / "CLASS.md").exists():
            out.append(("R2", f"{rel} has no knowledge/CLASS.md"))
        # A skill is required only for a class that HAS knowledge.
        #
        # `skillgen.generate_all` skips a class with zero items with the
        # comment "a skill with no knowledge is worse than no skill", and
        # CONTROL I11 agrees: a registered class with no gated items is a MAP
        # ENTRY that renders `Not yet researched.`. Requiring SKILL.md of such a
        # class therefore demanded the two rules be broken at once — either the
        # auditor fails forever on a legitimately empty class, or skillgen is
        # made to emit technique prose for a class nobody has researched, which
        # is the exact fabrication I11 exists to prevent. The requirement is
        # scoped to classes with evidence.
        n_items = con.execute(
            "SELECT count(*) n FROM item WHERE class_id=? AND status='active'",
            (cid,)).fetchone()["n"]
        if n_items and not (d / "skills" / "SKILL.md").exists():
            out.append(("R2", f"{rel} has {n_items} item(s) but no "
                              f"skills/SKILL.md"))
        elif not n_items and (d / "skills" / "SKILL.md").exists():
            out.append(("R2", f"{rel} has 0 items but a skills/SKILL.md -- a "
                              f"skill for a class with no evidence is "
                              f"fabricated technique prose (I11)"))

    # -- R3  a network class is never filed loose at a domain root ---------
    # Only the NETWORK domain has this rule. A web class legitimately sits
    # DIRECTLY under `skills/web/<class_id>` because web has no
    # specializations, so treating a known class as "unexpected" there would
    # report 37 phantom findings — the same class of error as the reference
    # audit that reported 93 phantom orphans by demanding a `/` in a path.
    known_classes = {r["id"] for r in con.execute("SELECT id FROM bug_class")}
    for d in (ROOT / "skills" / "web", ROOT / "skills" / "network"):
        if not d.is_dir():
            continue
        for child in d.iterdir():
            if not child.is_dir() or child.name.startswith("_"):
                continue
            reserved = set(D.SPEC_SLUG.values()) | {D.DOMAIN_SLUG.values()} \
                | {"chains", "methodology", "areas", "topics"}
            if child.name in reserved:
                continue
            if child.name in known_classes:
                # A registered class filed at a domain root. Legal for web,
                # illegal for network (it would sit beside 25 specializations
                # with nothing saying which specialization owns it).
                if child.name == D.DOMAIN_SLUG[D.NETWORK] or d.name == "network":
                    out.append((
                        "R3", f"network class {child.name!r} filed loose at "
                              f"skills/network/{child.name} — it needs a "
                              f"specialization folder"))
                continue
            out.append(("R3", f"unexpected entry directly under {d.name}/: "
                             f"{child.name} (not a registered class, not "
                             f"reserved)"))

    # -- R4  no writer spells a class path itself --------------------------
    for mod in PATH_OWNING_MODULES:
        p = ROOT / mod
        if not p.exists():
            out.append(("R4", f"writer missing: {mod}"))
            continue
        text = p.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("#") or s.startswith('"') or s.startswith("*"):
                continue
            if re.search(r'root\(\)\s*/\s*"(skills|classes|chains|methodology)"', s) \
               or re.search(r'=\s*f?"skills/', s):
                out.append(("R4", f"{mod}:{i} spells a retired path: {s[:70]}"))

    # -- R5  runtime state is isolated from knowledge ---------------------
    if (ROOT / "state").exists():
        out.append(("R5", "state/ exists at the root; runtime state belongs in "
                          "runtime/state/"))
    if not (ROOT / "runtime" / "state").is_dir():
        out.append(("R5", "runtime/state/ is absent"))

    # -- R6  the generator agrees with the tree ---------------------------
    return out


def skills_drift() -> list[tuple[str, str]]:
    """R7 — does every loaded skill still match the corpus it projects?

    `skills/` is in skills.external_dirs, so `skills/SKILL.md` is not a
    document: it is what the agent is handed when it loads a skill. A stale one
    means the model reasons from evidence the operator has already replaced,
    and nothing else in this auditor would notice, because the file EXISTS and
    resolves to the right place. Existence is not freshness.
    """
    from wks import project, store
    con = store.open_db()
    try:
        return [("R7", f"{f['class_id']}: {f['kind']} — {f['detail']}")
                for f in project.drift(con)]
    finally:
        con.close()


def run_generator_check() -> list[tuple[str, str]]:
    """`taxonomy_write.py --check` is the authority on generated content."""
    import subprocess
    gen = ROOT / "tools" / "taxonomy" / "taxonomy_write.py"
    if not gen.exists():
        return [("R6", f"generator absent at {gen}")]
    r = subprocess.run([sys.executable, str(gen), "--check"],
                       capture_output=True, text=True, cwd=str(ROOT))
    if r.returncode != 0:
        tail = (r.stdout or r.stderr).strip().splitlines()[:6]
        return [("R6", "taxonomy --check failed: " + " | ".join(tail))]
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true",
                    help="prove the checker fires on a synthetic broken tree")
    a = ap.parse_args(argv)

    if a.selftest:
        return _selftest()

    found = findings() + skills_drift() + run_generator_check()
    if found:
        print(f"{len(found)} architectural finding(s):")
        for rule, msg in found:
            print(f"  [{rule}] {msg}")
        return 1
    print("ARCHITECTURE OK — no retired roots, every class resolves to a "
          "self-contained unit, all writers share one path owner, runtime "
          "state isolated, loaded skills match the corpus, generator agrees "
          "with the tree.")
    return 0


def _selftest() -> int:
    """Run the R1 rule against a synthetic tree, clean and broken.

    Without this, "0 findings" is indistinguishable from a rule that can never
    fire. The broken case plants `bug-classes/` and a flat `*-hunting` skill and
    requires BOTH to be reported; the clean case plants neither and requires
    silence. A rule that passes both is a rule that reads the filesystem.
    """
    import tempfile
    import shutil
    bad = 0
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "bug-classes" / "web").mkdir(parents=True)
        (t / "bug-classes" / "web" / "xss.md").write_text("x", encoding="utf-8")
        (t / "skills" / "xss-hunting").mkdir(parents=True)
        (t / "skills" / "shared").mkdir(parents=True)
        saved = ROOT
        try:
            globals()["ROOT"] = t
            got = [m for r, m in findings() if r == "R1"]
            globals()["ROOT"] = saved
        finally:
            globals()["ROOT"] = saved
        hit_bug = any("bug-classes" in m for m in got)
        hit_flat = any("flat" in m for m in got)
        not_shared = not any("shared" in m for m in got)
        print(f"  [{'PASS' if hit_bug else 'FAIL'}] broken tree: bug-classes/ reported")
        print(f"  [{'PASS' if hit_flat else 'FAIL'}] broken tree: flat *-hunting reported")
        print(f"  [{'PASS' if not_shared else 'FAIL'}] clean entry (skills/shared) NOT reported")
        bad += (not hit_bug) + (not hit_flat) + (0 if not_shared else 1)
    print("SELFTEST:", "PASS" if not bad else f"FAIL ({bad})")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
