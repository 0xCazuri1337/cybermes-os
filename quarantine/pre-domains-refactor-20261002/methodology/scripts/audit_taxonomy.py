"""Rule 9 audit: no vulnerability class may have two canonical homes.

    python methodology/scripts/audit_taxonomy.py

Checks, in order of how badly they break the map:

  1. DUPLICATE CANONICAL PAGES — two non-stub files claim the same class.
     This is the failure the whole canonical-home rule exists to prevent.
  2. DEAD POINTER — a stub whose canonical target does not exist. A pointer
     that points nowhere is worse than no pointer: it looks navigable.
  3. ORPHANED EVIDENCE — a db class with gated items but no canonical page.
     The first version of the renderer passed this silently while 26 items
     were unreachable from the tree.
  4. SECTION DRIFT — a class page missing a schema section, or carrying one
     in the wrong order. Rule 5 is a consistency claim and must be checkable.
  5. UNMARKED CONTENT — a section that is neither empty, nor `Not yet
     researched.`, nor gated prose. Invented technical content must not be
     able to sit in the tree looking researched.

Exit 0 = clean. Exit 1 = at least one finding, each printed with its path.
"""
from __future__ import annotations

import os
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from build_taxonomy import BUG_SECTIONS, CHAIN_SECTIONS, CLASS_HOME, db  # noqa: E402
from taxonomy_spec import SUBDOCS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
from wks import config, domains as _domains  # noqa: E402

# WKS_ROOT may be a Windows 8.3 short path (C:\\Users\\ADMINI~1\\...), but
# config resolves symlinks/aliases to the long form, so `relative_to(ROOT)`
# raised ValueError. Compare against the RESOLVED root.
ROOT = config.root().resolve()   # WKS_ROOT may be an 8.3 path
BC = _domains.domain_dir(_domains.WEB)
AC = _domains.domain_dir(_domains.NETWORK)
NR = "Not yet researched."

# Declared sub-documents, as paths relative to bug-classes/. They are rendered
# by `tools/fill_subdocs.py` from the same gated corpus and live BESIDE a
# canonical class page, so they carry no BUG_SECTIONS schema and own no
# `bug_class` row. Reading one as a class page is what crashed this script:
# `BUG_SECTIONS.index("How it works")` raised ValueError, and a gate that
# raises reports nothing — rule R14 was uncheckable, not passing.
_SUBDOC_PATHS = {f"{d}/{f}" for d, files in SUBDOCS.items() for f in files}
# The comparison key is relative to `bug-classes/`, because that is what
# `p.relative_to(BC)` yields. SUBDOCS keys are REPO-relative ("bug-classes/…"),
# so strip that prefix before comparing — otherwise every declared sub-doc
# reads as missing, which is the one thing a liveness check must not do.
_SUBDOC_RELPATHS = {r[len("bug-classes/"):] if r.startswith("bug-classes/") else r
                    for r in _SUBDOC_PATHS}
# Bare stems of every declared sub-doc, so the schema check can tell a
# sub-doc from a canonical class page (they have different schemas).
_SUBDOC_STEMS = {r.rsplit('/', 1)[-1] for r in _SUBDOC_RELPATHS}

# rank for the order check; unknown sections must NOT raise. A schema check
# that crashes on unexpected input cannot report the unexpected input.
_SECTION_RANK = {s: i for i, s in enumerate(BUG_SECTIONS)}


def is_stub(txt: str) -> bool:
    return "Pointer — not the canonical page" in txt[:400]


def _rel(p: pathlib.Path) -> str:
    """Repo-relative path, tolerant of a Windows 8.3 short-path WKS_ROOT.

    `Path.relative_to` raises when the two spellings differ
    (`C:\\Users\\ADMINI~1\\...` vs `C:\\Users\\Administrator\\...`) and
    realpath does NOT expand the 8.3 form, so fall back to os.path.relpath,
    which compares by identity.
    """
    try:
        return p.relative_to(ROOT).as_posix()
    except ValueError:
        return pathlib.PurePath(
            os.path.relpath(str(p), str(ROOT))).as_posix()


def main() -> int:
    findings: list[str] = []
    canon: dict[str, list[str]] = defaultdict(list)

    # Three file kinds, three schemas. Only the class page is checked against
    # BUG_SECTIONS: the four per-class projections and HISTORY.md (provenance)
    # carry none, and a chain file has its own CHAIN_SECTIONS, audited below.
    # MEASURED: including the side files reported 38 + 15 false DUPLICATE
    # CANONICAL, and including chains reported every chain as SCHEMA DRIFT.
    pages = [p for p in BC.rglob("*.md")
             if p.name not in ("README.md", "SKILL.md", "EVIDENCE.md",
                                "CHAINS.md", "HISTORY.md")
             and "chains" not in p.parts]

    # 1 + 4 + 5
    for p in pages:
        txt = p.read_text(encoding="utf-8")
        rel = str(p.relative_to(BC).as_posix())

        # Declared sub-documents are audited for presence, not for the
        # class-page schema — they have no canonical home and no bug_class row.
        if rel in _SUBDOC_RELPATHS:
            if not txt.strip():
                findings.append(f"EMPTY SUBDOC  {_rel(p)}")
            continue

        # A migrated file opens with a provenance banner, so line 1 is a
        # comment shared by every bundle.
        _tl = [x for x in txt.splitlines()
              if not x.lstrip().startswith("<!--")]
        title = (_tl[0] if _tl else "").lstrip("# ").strip()
        if is_stub(txt):
            # 2. dead pointer. The stub renders its canonical home in TWO
            # forms on one line -- a markdown link target and a bare
            # backticked path. Reading the first backtick span took the PROSE
            # form (`web/authorization/`) and called 7 healthy pointers dead.
            import re as _re
            target = ""
            for line in txt.splitlines():
                if line.startswith("**Canonical home:**"):
                    m = _re.search(r"\]\(([^)]+)\)", line)
                    target = m.group(1) if m else (
                        line.split("`")[1] if "`" in line else "")
                    break
            if not target:
                findings.append(f"STUB HAS NO TARGET  {_rel(p)}")
            elif not (p.parent / target).resolve().exists():
                findings.append(f"DEAD POINTER  {_rel(p)} -> {target}")
            continue
            continue
        canon[title].append(_rel(p))

        # A sub-document has its OWN schema. Applying the class-page schema
        # reported every sub-doc as SECTION DRIFT (MEASURED: 23) when the real
        # contract is only that a sub-doc is non-empty and carries the gate
        # marker.
        if p.name in _SUBDOC_STEMS:
            _tl2 = [ln[3:].strip() for ln in txt.splitlines()
                    if ln.startswith("## ")]
            if not _tl2:
                findings.append(f"SUBDOC HAS NO SECTIONS  {_rel(p)}")
            if NR in txt and "item" not in txt.lower():
                findings.append(
                    f"SUBDOC UNMARKED CONTENT  {_rel(p)}  "
                    f"reads 'Not yet researched' but claims no gated item")
            continue

        secs = [ln[3:].strip() for ln in txt.splitlines() if ln.startswith("## ")]
        if secs != list(BUG_SECTIONS):
            missing = [s for s in BUG_SECTIONS if s not in secs]
            extra = [s for s in secs if s not in BUG_SECTIONS]
            order_ok = secs == sorted(secs, key=lambda s: _SECTION_RANK.get(s, 99))
            findings.append(
                f"SECTION DRIFT  {_rel(p)}  "
                f"missing={missing} unexpected={extra} order_ok={order_ok}")

        # 5. every section must be empty, NR, or substantive
        cur = None
        body: dict[str, list[str]] = defaultdict(list)
        for ln in txt.splitlines():
            if ln.startswith("## "):
                cur = ln[3:].strip()
            elif cur:
                body[cur].append(ln)
        for s, lines in body.items():
            content = "\n".join(lines).strip()
            if not content or content == NR:
                continue
            if len(content) < 40:
                findings.append(
                    f"THIN SECTION  {_rel(p)} :: {s} "
                    f"({len(content)} chars — too short to be gated prose)")

    for title, ps in sorted(canon.items()):
        if len(ps) > 1:
            findings.append(f"DUPLICATE CANONICAL  {title}: {ps}")

    # 3. orphaned evidence
    con = db()
    for (cid,) in con.execute("select id from bug_class"):
        n = con.execute("select count(*) from item where class_id=?", (cid,)).fetchone()[0]
        if n and cid not in CLASS_HOME:
            findings.append(f"ORPHANED EVIDENCE  class {cid}: {n} items, no CLASS_HOME")
    home_stems = {v.split("/")[-1][:-3] for v in CLASS_HOME.values()}
    for cid, home in sorted(CLASS_HOME.items()):
        # R14 must resolve each entry to where the merged generator
        # writes it, not to the retired bug-classes/ path.
        try:
            _c = db()
            _hp = _domains.domain_dir(
                _domains.domain_of(_c, cid)) / cid / "CLASS.md"
            _c.close()
        except Exception:
            _hp = BC / home
        if not _hp.exists():
            findings.append(f"CLASS_HOME MISSING FILE  {cid} -> {home}")
    con.close()

    # 5. chains, in BOTH domains. The merged tree splits them by the chain's
    # first-step class, so auditing one domain left 23 of 27 unverified.
    _chain_files = []
    for _dom in (_domains.WEB, _domains.NETWORK):
        _cdir = _domains.domain_dir(_dom) / "chains"
        if not _cdir.is_dir():
            continue
        for q in sorted(_cdir.glob("*.md")):
            # Only a DIRECT child of chains/ is a chain file, and a pointer
            # stub is not one: `chains/*.md` under a CLASS dir reported a
            # stub as a chain with 0 sections (MEASURED: 2 false findings).
            if q.name == "README.md" or q.parent != _cdir:
                continue
            if is_stub(q.read_text(encoding="utf-8")):
                continue
            _chain_files.append(q)
    # the two appendices are verbatim hand-authored prose, not schema
    _APX = ("Narrative (authored)", "Full digest (authored)")
    for p in _chain_files:
        # Scan the GENERATED section only. An authored digest embedded as an
        # appendix contributes its own `## ` headings (`Sequence`, ...), and
        # counting them reported every chain that has a digest as drifted
        # (MEASURED: 4 files, up to 23/11 sections).
        _gen = p.read_text(encoding="utf-8").split("## Narrative (authored)")[0]
        _gen = _gen.split("## Full digest (authored)")[0]
        secs = [ln[3:].strip() for ln in _gen.splitlines()
                if ln.startswith("## ") and ln[3:].strip() not in _APX]
        _order = [x for x in secs if x in CHAIN_SECTIONS]
        _extra = [x for x in secs if x not in CHAIN_SECTIONS]
        if _order != list(CHAIN_SECTIONS) or _extra:
            findings.append(
                f"CHAIN SCHEMA DRIFT  {_rel(p)}  "
                f"{len(_order)}/{len(CHAIN_SECTIONS)} sections"
                + (f"  extra={_extra}" if _extra else ""))

    # 6. declared sub-documents must exist. Without this the SUBDOCS entry is
    # inert: deleting a sub-doc would leave the spec claiming a file the tree
    # no longer has, and `--check` would pass.
    present = {str(p.relative_to(BC).as_posix()) for p in pages}
    for rel in sorted(_SUBDOC_RELPATHS):
        if rel not in present:
                # sub-docs live in the owning bundle topics/ now
                _found = any(_domains.domain_dir(d).rglob(rel)
                             for d in (_domains.WEB, _domains.NETWORK))
                if not _found:
                    findings.append(
                        f"MISSING SUBDOC  {rel}  declared in taxonomy_spec.SUBDOCS")

    print(f"audited {len(pages)} bug-class files ({len(_SUBDOC_PATHS)} declared sub-docs), "
          f"{len(canon)} canonical classes, {len(_chain_files)} chain files")
    if findings:
        print(f"\n{len(findings)} finding(s):")
        for f in findings:
            print("  " + f)
        return 1
    print("OK — one canonical home per class, no dead pointers, no orphaned evidence, "
          "schemas uniform")
    return 0


if __name__ == "__main__":
    sys.exit(main())