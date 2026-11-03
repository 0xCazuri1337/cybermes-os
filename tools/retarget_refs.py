"""Rewrite references from the retired tree into the canonical skills/ tree.

A restructure that moves 200 files breaks every link that pointed at them, and
the broken links are spread across hand-written prose (`CONTROL/`, `README.md`,
`methodology/`) as well as generated pages. That is the actual cost of the
migration, and it is invisible until `tools/audit_refs.py` reports it.

This is a REWRITER, not a search-and-replace: each old path is translated
through the same two maps the generator uses --

    old class page  ->  skills/<Domain>/<class_id>/CLASS.md
    old topic page  ->  skills/<Domain>/topics/<rest>
    old stub        ->  same mapping as the page it pointed at
    old chain file  ->  skills/<Domain>/chains/<name>

-- so a rewritten link points at the file the generator actually writes. A
regex that merely deleted `bug-classes/` would produce plausible-looking links to
files that do not exist, which is worse than leaving them broken.

Relativity is preserved: a link's depth changes when its target moves, so the
new `../` prefix is recomputed from the two absolute paths rather than copied.

    python tools/retarget_refs.py --dry     # report, write nothing
    python tools/retarget_refs.py --apply
"""
from __future__ import annotations

import argparse
import os
import posixpath
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from wks import config, domains  # noqa: E402

# R11: generated files belong to their generator. Editing one here
# makes `taxonomy_write.py --check` report permanent drift, and the
# next generator run silently reverts the fix. Retarget only
# hand-authored prose; a generated page must be FIXED IN ITS GENERATOR.
GENERATED_MARKERS = (
    "generated from db/wks.db",
    "GENERATED from db/wks.db",
    "DO NOT HAND-EDIT",
    "generated from `db/wks.db`",
)

MD_LINK = re.compile(r"\]\(([^)#][^)]*)\)")
CODE_PATH = re.compile(r"`([A-Za-z0-9_./\-]+\.(?:md|py|json|db))`")

SKIP_DIRS = {"__pycache__", ".git", "quarantine", "eval", "research",
             "node_modules", ".scratch"}


def _build_maps() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """(class pages, topic pages, chains) -- old repo-relative path -> new."""
    sys.path.insert(0, str(ROOT / "tools" / "taxonomy"))
    from build_taxonomy import CLASS_HOME, STEM_TO_CLASS
    from taxonomy_spec import CLASSES, STUBS

    con = sqlite3.connect(f"file:{config.db_path()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row

    pages: dict[str, str] = {}
    for cid, rel in CLASS_HOME.items():
        dom = domains.DOMAIN_LABEL[domains.domain_of(con, cid)]
        pages[f"bug-classes/{rel}"] = f"{domains.class_rel(cid, con)}/CLASS.md"

    # Every CLASSES row that is NOT a canonical class page is a sub-topic.
    canonical = set(CLASS_HOME.values())
    for path, _t, _c, _o, _d in CLASSES:
        if path in canonical:
            continue
        root, rest = path.split("/", 1)
        dom = "Network + AD" if root == "network" else "Web"
        pages[f"bug-classes/{path}"] = f"skills/{domains.DOMAIN_SLUG[dom]}/topics/{rest}"

    # POINTER STUBS. Their `canonical` is a path RELATIVE TO THE STUB'S OWN
    # DIRECTORY (`../client-side/clickjacking.md`), not to the repo root -- so
    # resolving it against ROOT silently produced a key that matched nothing and
    # the stub kept pointing into the retired tree.
    for stub_path, (_t, canon, _w) in STUBS.items():
        if not canon:
            continue
        stub_dir = stub_path.rsplit("/", 1)[0] if "/" in stub_path else ""
        joined = posixpath.normpath(posixpath.join(stub_dir, canon))
        tgt = pages.get(joined)
        if tgt:
            pages.setdefault(stub_path, tgt)

    chains: dict[str, str] = {}
    from build_taxonomy import CHAIN_HOME
    for ckey, rel in CHAIN_HOME.items():
        name = rel.split("/")[-1] if "/" in rel else rel
        # chain_key -> the file the generator wrote in the merged tree
        owner = _chain_owner_from_db(con, ckey)
        if owner:
            chains[f"attack-chains/{name}"] = f"skills/{domains.DOMAIN_SLUG[owner]}/chains/{name}"
            chains[f"chains/{ckey}.md"] = f"skills/{domains.DOMAIN_SLUG[owner]}/chains/{ckey}.md"

    # ALIASES. Migrated content does not name paths the way the tree does: it
    # says `classes/xxe.md` (the old flat evidence dir) or `web/xss/xss.md` (the
    # CLASS_HOME key without its `bug-classes/` prefix). Registering only the
    # `bug-classes/`-prefixed form retargets almost nothing while REPORTING
    # hundreds of dead links -- the map looks correct and matches nothing.
    for old_path, new_path in list(pages.items()):
        if old_path.startswith("bug-classes/"):
            pages.setdefault(old_path[len("bug-classes/"):], new_path)
    # `classes/<id>.md` -> the bundle's EVIDENCE.md
    for cid, rel in CLASS_HOME.items():
        dom = domains.DOMAIN_LABEL[domains.domain_of(con, cid)]
        pages.setdefault(f"classes/{cid}.md", f"{domains.class_rel(cid, con)}/DIGEST.md")
    # AREA READMEs are generated from README_FOR, not CLASSES, so they need
    # their own alias or every `../bug-classes/api/README.md` in methodology/
    # stays dead. They now live under skills/<domain>/areas/<area>/README.md.
    from taxonomy_spec import README_FOR, SUBDOCS

    # SUBDOC PAGES. `blind-xss.md`, `reflected-xss.md`, `store-xss.md` and their
    # siblings are declared in SUBDOCS, not in CLASSES, so neither CLASS_HOME nor
    # CLASSES ever named them and every reference to one was unresolvable.
    # They now live at skills/<domain>/<class>/topics/<file>.
    # MEASURED: SUBDOCS keys are ALREADY prefixed (`bug-classes/web/xss`) and the
    # values are BARE filenames, so a first attempt that joined them as
    # `<key>/<file>` registered nothing at all and the map size did not move.
    for _d, _fs in SUBDOCS.items():
        _area = _d[len("bug-classes/"):] if _d.startswith("bug-classes/") else _d
        for _f in _fs:
            _cid = next((c for c, rel in CLASS_HOME.items()
                         if rel.rsplit("/", 1)[-1] == _area.rsplit("/", 1)[-1]
                         or rel.endswith(_area)), None)
            # fill_subdocs writes these into the CLASS's topics/, so that is
            # where the map must point. Sending them to the DOMAIN's topics/
            # produced 23 links to files that were never written there.
            # Resolved through domains.class_rel so this table cannot drift
            # from the layout the generator actually writes.
            _tgt = f"{domains.class_rel(_cid, con)}/topics/{_f}"
            pages.setdefault(f"{_d}/{_f}", _tgt)
            pages.setdefault(_f, _tgt)
    for old_area in list(pages):
        pass
    for area in list(README_FOR):
        if area.startswith("bug-classes/"):
            rel = area[len("bug-classes/"):]
            _dom = domains.NETWORK if rel.startswith("network") else domains.WEB
            rel2 = rel[len("network"):].lstrip("/") if rel.startswith("network") else rel
            tgt = f"skills/{domains.DOMAIN_SLUG[_dom]}/areas/{rel2}/README.md"
            # README_FOR keys are DIRECTORIES (`bug-classes/web/xss`), but a
            # markdown link names the FILE (`.../web/xss/README.md`). Register
            # both forms or every `../bug-classes/<area>/README.md` stays dead.
            pages.setdefault(area, tgt)
            pages.setdefault(f"{area}/README.md", tgt)
            pages.setdefault(f"{rel}", tgt)
            pages.setdefault(f"{rel}/README.md", tgt)
    for area in list(README_FOR):
        if area == "attack-chains":
            pages.setdefault(area, "skills/web/chains/README.md")
            pages.setdefault(f"{area}/README.md", "skills/web/chains/README.md")
    # The two ROOT indexes are emitted from R["bug-classes"], which has no
    # README_FOR key at all, so nothing above registered them.
    pages.setdefault("bug-classes/README.md", "skills/README.md")
    pages.setdefault("bug-classes", "skills/README.md")
    pages.setdefault("bug-classes/web/README.md", "skills/web/areas/web/README.md")
    pages.setdefault("attack-chains/README.md", "skills/web/chains/README.md")
    # STUB targets are written as `../<area>/<name>.md` relative to the stub's own
    # directory. A link like `../client-side/clickjacking.md` therefore names a
    # PATH RELATIVE TO bug-classes/, not to the repo root.
    for old_path, new_path in list(pages.items()):
        if old_path.startswith("bug-classes/"):
            rel = old_path[len("bug-classes/"):]
            pages.setdefault(rel, new_path)

    # `skills/<id>-hunting/SKILL.md` -> the bundle's SKILL.md
    for cid in CLASS_HOME:
        pages.setdefault(f"skills/{cid}-hunting/SKILL.md",
                         f"{domains.class_rel(cid, con)}/SKILL.md")

    # BARE FILENAMES. Content inside `bug-classes/web/injection/` referred to a
    # sibling as just `sql-injection.md`. In the merged tree that sibling became
    # `skills/Web/sqli/CLASS.md`, so the filename no longer identifies a path.
    # Index every generated filename to its new home; ambiguity (two pages with
    # one name in different areas) resolves to the first, which is deterministic.
    for old_path, new_path in list(pages.items()):
        if not old_path.startswith("bug-classes/"):
            continue
        fname = old_path.rsplit("/", 1)[-1]
        pages.setdefault(fname, new_path)
        # the form a POINTER STUB uses: `../<area>/<file>.md` relative to the
        # stub's own directory, i.e. area-relative `client-side/clickjacking.md`
        tail = old_path[len("bug-classes/"):]
        if "/" in tail:
            area, fn = tail.split("/", 1)
            pages.setdefault(f"{area}/{fn}", new_path)

    con.close()
    return pages, topics_from(pages), chains


def topics_from(pages: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in pages.items() if "/topics/" in v}


def dom_from(old_path: str) -> str:
    return "Network + AD" if old_path.startswith("bug-classes/network") else "Web"


def _chain_owner_from_db(con, chain_key: str) -> str | None:
    """Which domain half a chain belongs to, from the classes its steps traverse."""
    from build_taxonomy import CLASS_HOME
    rows = con.execute(
        """SELECT DISTINCT class_id FROM chain_step
           WHERE chain_id IN (SELECT id FROM chain WHERE chain_key=?)""",
        (chain_key,)).fetchall()
    hit = None
    for r in rows:
        cid = r["class_id"]
        if not cid or cid not in CLASS_HOME:
            continue
        try:
            d = domains.domain_of(con, cid)
        except KeyError:
            continue
        if d == domains.NETWORK:
            return "Network + AD"
        hit = hit or domains.DOMAIN_LABEL[d]
    return hit


def _chain_domain(con, body: str) -> str:
    """Which half a chain belongs to: the domain of the classes it steps through."""
    from build_taxonomy import CLASS_HOME
    hit = None
    for m in re.finditer(r"`([a-z0-9_]+)`", body[:1200]):
        cid = m.group(1)
        if cid in CLASS_HOME:
            try:
                d = domains.domain_of(con, cid)
                if d == domains.NETWORK:
                    return "Network + AD"
                hit = hit or domains.DOMAIN_LABEL[d]
            except KeyError:
                pass
    return hit or "Web"


def relink(src: Path, target_rel: str) -> str:
    """Rebuild a relative link from the SOURCE file to the new target.

    Both paths are resolved to ABSOLUTE first. Joining a repo-relative target
    onto a source that already lives under `skills/` produced
    `skills/Web/chains/x.md -> ../skills/Web/api_trust/CLASS.md`, which is a
    link that looks right and points nowhere.
    """
    tgt = (ROOT / target_rel).resolve()
    rel = os.path.relpath(tgt, src.parent.resolve()).replace("\\", "/")
    return rel


def rewrite(text: str, src: Path, pages, chains) -> tuple[str, int]:
    n = 0

    def md(m: re.Match) -> str:
        nonlocal n
        t = m.group(1)
        base = t.split("#")[0]
        if not base or base.startswith(("http://", "https://", "mailto:")):
            return m.group(0)
        # normalise to a repo-relative path
        # If this link was ALREADY rewritten, its target is a new-tree path and
        # stripping the `../` run yields the correct repo-relative key directly.
        # Without this the lookup below only ever ran on the exception path, so
        # an already-migrated link was re-processed into `skills/Web/skills/...`.
        _bare = re.sub(r"^(?:\.\./)+", "", base)
        # A link that ALREADY resolves in the current tree is left alone.
        # Retargeting it anyway rewrote generator output that was already
        # correct (MEASURED: 142 findings, up from 101), and it also broke
        # `knowledge/activity/*` READMEs whose `../README.md` was right to begin with
        # (10 files drifting on every `--check`).
        if (src.parent / base).exists():
            return m.group(0)
        rel = None
        if rel is None:
          try:
              _abs = (src.parent / base).resolve()
              rel = _abs.relative_to(ROOT).as_posix()
              # resolve() SUCCEEDS for a nonexistent path on Windows, so a link
              # into the retired tree resolved to
              # `skills/Web/bug-classes/...` -- inside ROOT, so no exception, and
              # the fallback never ran. The rewritten target was then a path that
              # does not exist. The existence check is what makes the fallback
              # reachable.
              if not _abs.exists():
                  rel = None
                  raise FileNotFoundError(base)
              # A link already rewritten by an earlier pass still carries its
              # original `../` run. Strip it and re-resolve, or it stays one
              # directory too high and never resolves.
              if base.startswith("../"):
                  _alt = (src.parent / _bare).resolve()
                  if _alt.exists():
                      rel = _alt.relative_to(ROOT).as_posix()
          except (ValueError, OSError):
              # The target is GONE (retired tree), so resolve() cannot help. Strip
              # the leading ../ run textually and look the remainder up: a link
              # written as `../bug-classes/api/README.md` from methodology/ names
              # `bug-classes/api/README.md` regardless of whether it exists.
              cand = re.sub(r"^(?:\.\./)+", "", base)
              if cand in pages or cand in chains:
                  rel = cand
              elif "/" not in cand and (cand in pages or cand in chains):
                  # bare sibling filename
                  rel = cand
              elif base in pages or base in chains:
                  rel = base
              else:
                  return m.group(0)
        new = pages.get(rel) or chains.get(rel)
        if not new:
            return m.group(0)
        n += 1
        frag = ("#" + t.split("#", 1)[1]) if "#" in t else ""
        return f"]({relink(src, new)}{frag})"

    def code(m: re.Match) -> str:
        nonlocal n
        t = m.group(1)
        # A backticked path that ALREADY resolves in the current tree is left
        # alone, for the same reason as the link case: `[`../README.md`]`
        # inside `skills/<domain>/areas/<area>/` is correct, and rewriting only
        # the LABEL while the link stayed put made the two halves disagree
        # (MEASURED: permanent R15 drift on one area README).
        if (src.parent / t).exists():
            return m.group(0)
        for prefix in ("../", "./"):
            if t.startswith(prefix):
                t = t[len(prefix):]
        new = pages.get(t) or chains.get(t)
        if not new:
            return m.group(0)
        n += 1
        return f"`{new}`"

    # Both substitutions must run against the SAME original text. Running the
    # backtick pass first rewrote the LINK LABEL while leaving the link TARGET
    # (`](../bug-classes/...)`) pointing into the retired tree, so the file kept
    # reporting a dead link that the map could resolve. Order is not cosmetic
    # here: the second pass decides whether the first pass's output is coherent.
    original = text
    text = MD_LINK.sub(md, original)
    text = CODE_PATH.sub(code, text)
    return text, n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="retarget_refs")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)

    pages, _topics, chains = _build_maps()
    print(f"map: {len(pages)} class/topic pages, {len(chains)} chain files")
    if not (ROOT / "bug-classes").exists() and not (ROOT / "chains").exists():
        print("  (source tree already retired -- nothing to retarget from)")

    changed: list[tuple[Path, int]] = []
    for p in sorted(ROOT.rglob("*.md")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Skip generated pages (R11). Their links are the GENERATOR's problem.
        if any(mk in text[:900] for mk in GENERATED_MARKERS):
            continue
        new, n = rewrite(text, p, pages, chains)
        if n:
            changed.append((p, n))
            if a.apply:
                p.write_text(new, encoding="utf-8")
    total = sum(n for _p, n in changed)
    print(f"\n{'wrote' if a.apply else 'would rewrite'} {len(changed)} files, "
          f"{total} references")
    for p, n in sorted(changed, key=lambda t: -t[1])[:15]:
        print(f"  {n:4}  {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())