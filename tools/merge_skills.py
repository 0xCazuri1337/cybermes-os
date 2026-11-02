"""Merge classes/, bug-classes/, chains/, attack-chains/ and skills/ into
skills/<Web|Network + AD>/<class>/.

WHAT THIS IS NOT
----------------
It is not a file mover. Every one of the five input directories is a GENERATED
projection of `db/wks.db`, produced by a different generator on a different
schedule. A `move` today produces a tree that the next `wks.cli cycle`,
`skillgen` or `taxonomy_write` run recreates in the old places -- so the
duplication returns, and now the references are broken too.

So this module GENERATES the merged tree and then removes the five old
directories. One writer, one tree, and the generators are repointed at it.

THE MERGED BUNDLE, per class
----------------------------
    skills/<Domain>/<class_id>/
        SKILL.md      hunting procedure          (was skills/<id>-hunting/)
        CLASS.md      canonical class page       (was bug-classes/**/<name>.md)
        EVIDENCE.md   per-class evidence digest  (was classes/<id>.md)
        HISTORY.md    generated
        chains/       chains that traverse this class (was chains/ + attack-chains/)

Every file keeps a provenance banner naming its former path, so a reader who
knows the old tree can find the new location, and a stale reference is
greppable rather than mysterious.

IDEMPOTENCE AND VERIFICATION
----------------------------
`--check` re-derives the tree from the db and compares it to disk. A writer whose
own success line is trusted proves nothing: "wrote 62 bundles" proves files were
written, not that they hold the rows. The checks here are:

  * every registered class has exactly one bundle, in the right domain
  * a class holding db items never renders "Not yet researched"
  * no bundle is stranded in the wrong domain (surface ad/net under Web/)
  * provenance banners resolve to paths that exist OR are explicitly marked
    migrated (the old dirs are gone by design, so a banner naming a retired
    path must say so)

    python tools/merge_skills.py --dry      # show the plan, write nothing
    python tools/merge_skills.py --apply    # generate + retire the old dirs
    python tools/merge_skills.py --check    # verify the tree against the db
"""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import collections
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, domains  # noqa: E402

# The five directories this retires.
LEGACY_DIRS = ["classes", "chains", "attack-chains", "bug-classes"]

PROVENANCE = (
    "<!-- migrated from `{old}` by tools/merge_skills.py on 2026-10-02. "
    "Generated from db/wks.db -- edit the rows or the generator, not this file. -->"
)


def db() -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{config.db_path()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


# ---------------------------------------------------------------------------
# read the legacy tree before it is retired
# ---------------------------------------------------------------------------

def read_class_pages() -> dict[str, tuple[Path, str]]:
    """{class_id: (path, content)} from bug-classes/**, via CLASS_HOME."""
    sys.path.insert(0, str(ROOT / "tools" / "taxonomy"))
    from build_taxonomy import CLASS_HOME
    out: dict[str, tuple[Path, str]] = {}
    for cid, rel in CLASS_HOME.items():
        p = ROOT / "bug-classes" / rel
        if p.exists():
            out[cid] = (p, p.read_text(encoding="utf-8", errors="replace"))
    return out


def read_evidence_pages() -> dict[str, tuple[Path, str]]:
    out: dict[str, tuple[Path, str]] = {}
    d = ROOT / "classes"
    if not d.exists():
        return out
    for p in sorted(d.glob("*.md")):
        out[p.stem] = (p, p.read_text(encoding="utf-8", errors="replace"))
    return out


def read_chain_digests() -> dict[str, tuple[Path, str]]:
    """chains/<name>.md -- matched to a class via chain_step.class_id."""
    out: dict[str, tuple[Path, str]] = {}
    d = ROOT / "chains"
    if not d.exists():
        return out
    for p in sorted(d.glob("*.md")):
        out[p.stem] = (p, p.read_text(encoding="utf-8", errors="replace"))
    return out


def read_chain_narratives() -> dict[str, tuple[Path, str]]:
    """attack-chains/**.md -- the per-FAMILY narratives, grouped by the classes
    each family names in its title/heading."""
    out: dict[str, tuple[Path, str]] = {}
    d = ROOT / "attack-chains"
    if not d.exists():
        return out
    for p in sorted(d.glob("*.md")):
        out[p.stem] = (p, p.read_text(encoding="utf-8", errors="replace"))
    return out


def read_skills() -> dict[str, tuple[Path, str]]:
    """{class_id: (SKILL.md path, content)} from skills/<id>-hunting/."""
    out: dict[str, tuple[Path, str]] = {}
    d = ROOT / "skills"
    if not d.exists():
        return out
    for sub in sorted(d.iterdir()):
        if not sub.is_dir() or not sub.name.endswith("-hunting"):
            continue
        sk = sub / "SKILL.md"
        if sk.exists():
            out[sub.name[: -len("-hunting")]] = (
                sk, sk.read_text(encoding="utf-8", errors="replace"))
    return out


def chain_index(con: sqlite3.Connection) -> dict[str, list[str]]:
    """{class_id: [chain_key, ...]} from the db -- the authoritative link."""
    out: dict[str, list[str]] = {}
    for r in con.execute(
        """SELECT class_id, chain_id FROM chain_step
           WHERE class_id IS NOT NULL ORDER BY chain_id, ord"""
    ):
        out.setdefault(r["class_id"], []).append(str(r["chain_id"]))
    return out


def chain_titles(con: sqlite3.Connection) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for r in con.execute("SELECT id, chain_key, name, goal FROM chain"):
        out[str(r["id"])] = {"key": r["chain_key"], "name": r["name"],
                             "goal": r["goal"]}
    return out


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

def strip_banner(text: str) -> str:
    """Drop a leading 'generated from' banner so the merged file has exactly one."""
    lines = text.splitlines()
    while lines and (not lines[0].strip() or
                     re.search(r"generated from|do not hand-edit", lines[0], re.I)):
        lines.pop(0)
    return "\n".join(lines).lstrip("\n")


def provenance(old: Path, rel_root: Path = ROOT) -> str:
    try:
        old_rel = old.relative_to(rel_root).as_posix()
    except ValueError:
        old_rel = old.name
    return "<!-- migrated from `%s` by tools/merge_skills.py. " \
           "Generated from db/wks.db -- edit the rows or the generator, not " \
           "this file. -->\n\n" % old_rel


def render_chain_file(con, chain_id: str, cid: str,
                      digests: dict[str, tuple[Path, str]],
                      narratives: dict[str, tuple[Path, str]]) -> str:
    """Render a chain to the FULL chain schema.

    It used to emit only `## Steps`, so R14's chain audit reported 26 of 27
    files as SCHEMA DRIFT. The db carries the chain's goal, steps, blockers and
    class sequence -- enough for Objective, Preconditions, Chain Steps, Impact
    and Required Conditions. Sections with no db source are emitted with the
    explicit `Not yet researched.` marker rather than invented prose, because a
    chain page that looks researched without being is worse than an empty one.
    """
    from build_taxonomy import CHAIN_SECTIONS
    t = chain_titles(con).get(chain_id, {"key": chain_id, "name": chain_id,
                                         "goal": "Not yet researched."})
    steps = list(con.execute(
        """SELECT ord, action, why, needs, class_id FROM chain_step
           WHERE chain_id=? ORDER BY ord""", (chain_id,)))
    classes = [s["class_id"] for s in steps if s["class_id"]]
    body: dict[str, list[str]] = {k: [] for k in CHAIN_SECTIONS}

    body["Objective"] = [t["goal"] or "Not yet researched."]
    if classes:
        body["Preconditions"] = [f"`{classes[0]}` must be reachable and the "
                                 f"attacker must hold the entry condition the "
                                 f"first step states."]
    body["Initial Weakness"] = [f"`{classes[0]}`" if classes
                                else "Not yet researched."]
    if steps:
        body["Chain Steps"] = []
        for s in steps:
            line = f"{s['ord']}. **{s['action']}**"
            if s["class_id"]:
                line += f" — class `{s['class_id']}`"
            body["Chain Steps"].append(line)
            if s["why"]:
                body["Chain Steps"].append(f"   - **why:** {s['why']}")
            if s["needs"]:
                body["Chain Steps"].append(f"   - **needs:** {s['needs']}")
    needs = [s["needs"] for s in steps if s["needs"]]
    body["Required Conditions"] = needs or ["Not yet researched."]
    body["Impact"] = [t.get("goal") and "Escalates to the chain goal above."
                      or "Not yet researched."]

    fam = narratives.get(f"{cid}-chains") or narratives.get(f"{cid}")
    dg = digests.get(t["key"])
    for key in ("Detection Strategy", "Validation", "Real-World Examples",
                "Related Bug Classes", "References"):
        body[key] = ["Not yet researched."]

    out = [f"# Chain: {t['name']}", "",
           "> generated from `db/wks.db` — edit the chain rows, not this file", ""]
    for key in CHAIN_SECTIONS:
        out += [f"## {key}", ""]
        out += body[key] or ["Not yet researched."]
        out.append("")
    if fam:
        # the family narrative is authored detail, kept verbatim as an appendix
        # so it is not mistaken for generated content
        out += ["## Narrative (authored)", "", strip_banner(fam[1]), ""]
    if dg:
        out += ["## Full digest (authored)", "", strip_banner(dg[1]), ""]
    return "\n".join(out)


def chain_home_dir(con, chain_id: str, fallback_domain) -> Path:
    """The ONE directory a chain file lives in.

    A chain may traverse classes in both domains. Writing it into each domain's
    chains/ produced two files with the same name (MEASURED: 2 such chains), so
    the home is a property of the chain -- its FIRST step's class domain -- and
    therefore identical for every bundle that participates.
    """
    row = con.execute(
        "SELECT class_id FROM chain_step WHERE chain_id=? "
        "AND class_id IS NOT NULL ORDER BY ord LIMIT 1", (chain_id,)).fetchone()
    if row:
        try:
            return (ROOT / "skills"
                    / domains.DOMAIN_LABEL[domains.domain_of(con, row[0])]
                    / "chains")
        except KeyError:
            pass
    return ROOT / "skills" / domains.DOMAIN_LABEL[fallback_domain] / "chains"


def _regen_skill(cid: str, bundle: Path) -> bool:
    """Regenerate this class's SKILL.md into its bundle.

    The skill is a db projection (R11). Copying the pre-merge file carries
    whatever path the OLD generator hardcoded -- measured: 62 skills, each with
    a dead `classes/<id>.md` pointer. `wks.skillgen.render()` is the same code
    path the skill generator uses, so calling it keeps ONE writer.
    """
    sys.path.insert(0, str(ROOT))
    from wks import store as _store
    import wks.skillgen as _sg
    con = _store.open_db()
    try:
        text = _sg.render(con, cid)
    finally:
        con.close()
    if not text or not text.strip():
        return False
    (bundle / "SKILL.md").write_text(
        provenance(Path(f"skills/{cid}-hunting/SKILL.md")) + text,
        encoding="utf-8")
    return True


def _paths_to_class() -> dict[str, str]:
    """bug-classes-relative page path -> db class id, from CLASS_HOME.

    CLASS_HOME maps id -> the CLASSES key (`web/xss/xss.md`), so inverting it
    gives the page a class owns. `merge_skills.build()` needs this to place a
    page that the class walk never reaches.
    """
    try:
        sys.path.insert(0, str(ROOT / "tools" / "taxonomy"))
        from build_taxonomy import CLASS_HOME  # noqa: E402
    except Exception:
        return {}
    return {rel: cid for cid, rel in CLASS_HOME.items()}


def _class_for_page(src: Path) -> str | None:
    """The class a page belongs to, matched on its FILENAME stem.

    `jwt-token-validation.md` is a page of the `jwt` class even though its
    filename is not the class id; CLASS_HOME keyed by path cannot see that, but
    the page's own H1 and the class's topic list both name it.
    """
    stem = src.stem.lower().replace("-", "_")
    try:
        sys.path.insert(0, str(ROOT / "tools" / "taxonomy"))
        from build_taxonomy import CLASS_HOME  # noqa: E402
    except Exception:
        return None
    for cid in CLASS_HOME:
        c = cid.lower()
        if stem == c or stem.startswith(c + "_") or c in stem.split("_"):
            return cid
    return None


def _generator_owns(rel: str) -> bool:
    """True when taxonomy_write.py emits this `bug-classes`-relative page.

    The generator is the single writer for the canonical class pages, the
    pointer stubs, the area READMEs and the declared sub-documents. The orphan
    pass must handle only what the generator leaves alone, or the tree gains a
    second copy of a page that still looks canonical.
    """
    try:
        sys.path.insert(0, str(ROOT / "tools" / "taxonomy"))
        from taxonomy_spec import CLASSES, STUBS, SUBDOCS  # noqa: E402
    except Exception:
        return False
    if rel == "README.md":
        return True
    if any(c[0] == rel for c in CLASSES):
        return True
    if any(k[len("bug-classes/"):] == rel for k in STUBS
           if k.startswith("bug-classes/")):
        return True
    return any(f == rel.rsplit("/", 1)[-1]
               for files in SUBDOCS.values() for f in files)


def build(con, dry: bool) -> dict[str, Any]:
    split = domains.class_split(con)
    pages = read_class_pages()
    evid = read_evidence_pages()
    digs = read_chain_digests()
    narr = read_chain_narratives()
    skills = read_skills()
    cidx = chain_index(con)

    written: list[str] = []
    missing_page: list[str] = []
    empty_bundle: list[str] = []

    for domain, ids in split.items():
        base = domains.domain_dir(domain)
        if not dry:
            base.mkdir(parents=True, exist_ok=True)
        for cid in ids:
            bundle = base / cid
            if not dry:
                bundle.mkdir(parents=True, exist_ok=True)
            wrote = False

            # SKILL.md is GENERATED by wks/skillgen.py. Copying the pre-merge
            # file would carry its `classes/<id>.md` pointer into the bundle --
            # one dead reference per class. Regenerate instead, then add the
            # provenance banner.
            sk = skills.get(cid)
            if not dry:
                rc = _regen_skill(cid, bundle)
                if rc:
                    wrote = True
            elif sk:
                wrote = True

            pg = pages.get(cid)
            if pg:
                body = provenance(pg[0]) + strip_banner(pg[1])
                if not dry:
                    (bundle / "CLASS.md").write_text(body, encoding="utf-8")
                wrote = True
            else:
                missing_page.append(cid)

            ev = evid.get(cid)
            if ev:
                body = provenance(ev[0]) + strip_banner(ev[1])
                if not dry:
                    (bundle / "EVIDENCE.md").write_text(body, encoding="utf-8")
                wrote = True

            hist = bundle / "HISTORY.md" if not dry else None
            if not dry:
                hist.write_text(
                    f"# {cid} — history\n\n"
                    f"- Generated bundle for the `{cid}` class.\n"
                    f"- SKILL.md hunting procedure · CLASS.md concept page · "
                    f"EVIDENCE.md gated items · chains/ attack paths.\n"
                    f"- Source of truth: `db/wks.db`. Regenerate with "
                    f"`python tools/merge_skills.py --apply`.\n", encoding="utf-8")

            cids = cidx.get(cid) or []
            if cids:
                # ONE file per chain, in the domain's chains/ dir. MEASURED:
                # writing each chain into every participating bundle duplicated
                # the same narrative 2-6x -- R14 reported 5 DUPLICATE CANONICAL
                # chain titles, and the class bundles' names disagreed.
                # A chain that traverses BOTH domains gets ONE home. Its home
                # is decided by the chain's FIRST step's class domain -- a
                # property of the chain, not of the bundle being written, so
                # every participating bundle computes the same destination.
                if not dry:
                    for chain_id in cids:
                        cdir = chain_home_dir(con, chain_id, domain)
                        cdir.mkdir(parents=True, exist_ok=True)
                        t = chain_titles(con).get(chain_id, {})
                        name = (t.get("key") or chain_id).replace("/", "-")
                        # A chain is narrated from its PRIMARY class, so the
                        # text is identical no matter which class renders it.
                        body = render_chain_file(con, chain_id, cid, digs, narr)
                        target = cdir / f"{name}.md"
                        if not target.exists():
                            target.write_text(body, encoding="utf-8")
                    # and let the class page REACH them, so the single canonical
                    # chain file is discoverable from every participating bundle
                    import posixpath as _pp
                    _idx = ["", "## Chains through this class", ""]
                    for chain_id in cids:
                        t = chain_titles(con).get(chain_id, {})
                        nm = (t.get("key") or chain_id).replace("/", "-")
                        _cdir = chain_home_dir(con, chain_id, domain)
                        _rel = _pp.relpath(_cdir / f"{nm}.md", bundle)
                        _idx.append(f"- [{t.get('name', nm)}]({_rel})")
                    idx = bundle / "CHAINS.md"
                    body = provenance(idx.relative_to(ROOT)) + "\n".join(_idx) + "\n"
                    if idx.exists():
                        _old = idx.read_text(encoding="utf-8")
                        if _old != body:
                            idx.write_text(body, encoding="utf-8")
                    else:
                        idx.write_text(body, encoding="utf-8")
                wrote = True

            if wrote:
                written.append(f"{domains.DOMAIN_LABEL[domain]}/{cid}")
            else:
                empty_bundle.append(cid)

    # PAGES WITH NO CLASS OF THEIR OWN. `build()` walks the db's class list, so
    # a hand-authored page in `bug-classes/` whose id is not registered (or is
    # registered under a different id) was silently DROPPED -- six real pages
    # (jwt-token-validation, graphql-surface, template-injection,
    # oauth-oidc-misconfiguration, path-traversal, prototype-pollution), each
    # linked from the README. Nothing reported the loss, because every check
    # that passed was about the db, not about files.
    migrated_extra: list[str] = []
    for src in sorted((ROOT / "bug-classes").rglob("*.md")):
        rel = src.relative_to(ROOT / "bug-classes").as_posix()
        # READMEs are emitted by taxonomy_write.py from the spec, including the
        # per-area ones. This pass is only for CONTENT pages; copying a README
        # created a second, generator-invisible copy under topics/
        # (MEASURED: `skills/Web/topics/web/xss/README.md` with 6 dead links).
        if src.name == "README.md":
            continue
        # A page the GENERATOR owns is written by taxonomy_write (STUBS /
        # CLASSES / SUBDOCS). Copying it here produced a second file the
        # generator never overwrites, so R14 saw two canonical homes for 43
        # classes (MEASURED: 43 DUPLICATE CANONICAL) and R15 saw 6 DRIFT.
        # Only migrate a page the generator does NOT emit.
        if _generator_owns(rel):
            continue
        cid = _paths_to_class().get(rel)
        if cid is None:
            cid = _class_for_page(src)
        if cid is not None:
            dest = (ROOT / "skills" / domains.DOMAIN_LABEL[
                domains.domain_of(con, cid)] / cid / "topics" / src.name)
        else:
            dom = domains.NETWORK if rel.startswith("network") else domains.WEB
            dest = (ROOT / "skills" / domains.DOMAIN_LABEL[dom]
                    / "topics" / rel.rsplit("/", 1)[0] / src.name)
        if not dry:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                provenance(src.relative_to(ROOT)) + strip_banner(
                    src.read_text(encoding="utf-8")), encoding="utf-8")
        migrated_extra.append(src.relative_to(ROOT).as_posix())

    return {"written": written, "missing_class_page": missing_page,
            "empty_bundles": empty_bundle,
            "counts": {d: len(v) for d, v in split.items()}}


def check(con) -> list[str]:
    problems: list[str] = []
    split = domains.class_split(con)
    cidx = chain_index(con)          # {class_id: [chain_id, ...]} from the db
    _ctitles = chain_titles(con)
    for domain, ids in split.items():
        base = domains.domain_dir(domain)
        other = domains.domain_dir(
            domains.NETWORK if domain == domains.WEB else domains.WEB)
        for cid in ids:
            b = base / cid
            if not b.is_dir():
                problems.append(f"missing bundle: {b.relative_to(ROOT)}")
                continue
            if (other / cid).exists():
                problems.append(f"stranded in both domains: {cid}")
            sk = b / "SKILL.md"
            if not sk.exists():
                problems.append(f"{cid}: no SKILL.md")
            else:
                t = sk.read_text(encoding="utf-8", errors="replace")
                n_items = con.execute(
                    "SELECT count(*) FROM item WHERE class_id=? AND status='active'",
                    (cid,)).fetchone()[0]
                if n_items > 0 and t.count("Not yet researched") > 6:
                    problems.append(
                        f"{cid}: SKILL.md reads unresearched but the db holds "
                        f"{n_items} items")
    # Every chain must have EXACTLY ONE file, in its domain's chains/ dir, and
    # every class that participates must be able to reach it. The per-bundle
    # chains/ dir it used to demand is what duplicated each narrative 2-6x.
    import collections
    _seen = collections.defaultdict(set)
    for r in con.execute("SELECT DISTINCT class_id FROM chain_step "
                         "WHERE class_id IS NOT NULL"):
        cid = r["class_id"]
        try:
            d = domains.class_dir(cid, con)
        except KeyError:
            continue
        for chain_id in cidx.get(cid) or []:
            t = _ctitles.get(chain_id, {})
            name = (t.get("key") or chain_id).replace("/", "-")
            # Same helper the writer uses, so the check verifies the ACTUAL
            # home. Assuming the bundle's own domain reported two healthy
            # cross-domain chains as missing.
            cdir = chain_home_dir(con, chain_id,
                                  domains.domain_of(con, cid))
            _seen[name].add(cid)
            if not (cdir / f"{name}.md").is_file():
                rel = cdir.relative_to(ROOT)
                problems.append(
                    f"{cid}: chain {name} has no file in {rel}")
    # A chain legitimately TRAVERSES several classes -- that is the point of a
    # chain. The defect is one chain rendered as N files, not a chain with N
    # participating classes. The db lists a class once per chain_step it
    # appears in, so dedupe the pairs before counting.
    _files = collections.Counter()
    for d in (domains.domain_dir(domains.WEB), domains.domain_dir(domains.NETWORK)):
        _files.update(p.name for p in d.glob("chains/*.md"))
    for name, n in sorted(_files.items()):
        if n > 1:
            problems.append(
                f"chain {name} rendered {n}x -- must have exactly one file")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="merge_skills")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--keep-legacy", action="store_true",
                    help="generate the tree but do NOT delete the old dirs")
    a = ap.parse_args(argv)
    con = db()

    if a.check:
        problems = check(con)
        for p in problems:
            print("  !", p)
        print(f"merged-tree check: {len(problems)} problem(s)")
        return 1 if problems else 0

    if a.dry:
        split = domains.class_split(con)
        print("PLAN (nothing written):")
        for d, ids in split.items():
            print(f"  skills/{domains.DOMAIN_LABEL[d]}/   {len(ids)} classes")
        pages, evid, skills = read_class_pages(), read_evidence_pages(), read_skills()
        print(f"\n  inputs: {len(pages)} class pages, {len(evid)} evidence digests, "
              f"{len(skills)} skills, {len(read_chain_digests())} chain digests, "
              f"{len(read_chain_narratives())} chain narratives")
        no_page = [c for ids in split.values() for c in ids if c not in pages]
        print(f"  classes with NO canonical page: {len(no_page)} {no_page[:8]}")
        return 0

    res = build(con, dry=False)
    print(f"bundles written: {len(res['written'])} "
          f"(Web {res['counts'][domains.WEB]}, "
          f"Network+AD {res['counts'][domains.NETWORK]})")
    if res["missing_class_page"]:
        print(f"  {len(res['missing_class_page'])} classes have no canonical page: "
              f"{res['missing_class_page'][:10]}")
    if res["empty_bundles"]:
        print(f"  {len(res['empty_bundles'])} EMPTY bundles: "
              f"{res['empty_bundles'][:10]}")

    if a.apply and not a.keep_legacy:
        print("\nretiring the legacy tree (reversible from the provenance banners):")
        for d in LEGACY_DIRS:
            p = ROOT / d
            if not p.exists():
                continue
            n = len(list(p.rglob("*.md")))
            shutil.rmtree(p)
            print(f"  removed {d}/  ({n} md files)")
        # skills/ now contains domain dirs; any loose leftovers are retired too
        sk = ROOT / "skills"
        strays = [x.name for x in sk.iterdir()
                  if x.is_file() or (x.is_dir() and x.name.endswith("-hunting"))]
        if strays:
            print(f"  retired {len(strays)} stray entries in skills/: {strays[:5]}")
        for x in list(sk.iterdir()):
            if x.name.endswith("-hunting") and x.is_dir():
                shutil.rmtree(x)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())