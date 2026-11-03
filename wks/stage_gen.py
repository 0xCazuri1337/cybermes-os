
"""Staged generation with rollback for WKS projections."""
from __future__ import annotations
import hashlib
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

GENERATED_ARTIFACTS = {"SKILL.md", "DIGEST.md", "CLASS.md"}
MARKER = "<!-- GENERATED from db/wks.db — do not edit -->"


def _classes(con, classes):
    if classes is None:
        rows = con.execute("SELECT id FROM bug_class WHERE status!='retired' ORDER BY id").fetchall()
        classes = [r[0] for r in rows]
    out = []
    for cid in classes:
        n = con.execute("SELECT count(*) FROM item WHERE class_id=? AND status='active'", (cid,)).fetchone()[0]
        if n and n > 0:
            out.append(cid)
    return out


def _rel(con, cid):
    from . import domains
    return domains.class_rel(cid, con)


def _sha256(path):
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _validate_staging(staging_dir, classes, con):
    for cid in classes:
        rel = _rel(con, cid)
        for name in ("SKILL.md", "DIGEST.md"):
            p = staging_dir / rel / name
            if not p.is_file():
                raise RuntimeError("staging missing %s" % p)
            text = p.read_text(encoding="utf-8")
            if MARKER not in text:
                raise RuntimeError("staging header missing in %s" % p)
    staged = [p for p in staging_dir.rglob("SKILL.md")]
    if len(staged) != len(classes):
        raise RuntimeError("staging coverage mismatch: %d vs %d" % (len(staged), len(classes)))


def stage(con, classes=None, staging_dir=None):
    selected = _classes(con, classes)
    if staging_dir is None:
        staging_dir = Path(tempfile.mkdtemp(prefix="wks_stage_"))
    else:
        staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    from . import skillgen, pipeline
    for cid in selected:
        rel = _rel(con, cid)
        out_dir = staging_dir / rel
        out_dir.mkdir(parents=True, exist_ok=True)
        skill_content = skillgen.render(con, cid)
        (out_dir / "SKILL.md").write_text(skill_content, encoding="utf-8")
        digest_content = pipeline.markdown_report(con, cid)
        (out_dir / "DIGEST.md").write_text(digest_content, encoding="utf-8")
    _validate_staging(staging_dir, selected, con)
    return staging_dir


def _collect_staged(staging_dir):
    out = []
    for p in sorted(staging_dir.rglob("*")):
        if p.is_file() and p.name in GENERATED_ARTIFACTS:
            out.append((p, p.relative_to(staging_dir).as_posix()))
    return out


def _validate_staged_files(staging_dir):
    if not staging_dir.is_dir():
        raise RuntimeError("staging dir not found: %s" % staging_dir)
    if not _collect_staged(staging_dir):
        raise RuntimeError("staging dir contains no generated artifacts")


def promote(staging_dir):
    from . import config, store, manifest
    staging_dir = Path(staging_dir)
    _validate_staged_files(staging_dir)
    staged = _collect_staged(staging_dir)
    for p, rel in staged:
        if p.name in ("SKILL.md", "DIGEST.md"):
            text = p.read_text(encoding="utf-8")
            if MARKER not in text:
                return {"ok": False, "promoted": [], "rolled_back": False,
                        "error": "missing generated header in %s" % rel}
    root = config.root()
    backup_root = Path(tempfile.mkdtemp(prefix="wks_promote_backup_"))
    backups = {}
    try:
        for p, rel in staged:
            live = root / rel
            if live.exists():
                bp = backup_root / rel
                bp.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(live, bp)
                backups[rel] = bp
            else:
                backups[rel] = None
        for p, rel in staged:
            live = root / rel
            live.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, live)
        con = store.open_db(create=True)
        try:
            manifest.ensure_table(con)
            for p, rel in staged:
                class_id = Path(rel).parent.name
                artifact_type = {"SKILL.md": "skill", "DIGEST.md": "knowledge", "CLASS.md": "class"}.get(p.name, "projection")
                manifest.upsert(con, class_id, artifact_type, rel, content_sha256=_sha256(root / rel))
        finally:
            con.close()
    except Exception as e:
        for rel, bp in backups.items():
            live = root / rel
            try:
                if bp is None:
                    if live.exists():
                        live.unlink()
                else:
                    live.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(bp, live)
            except Exception:
                pass
        shutil.rmtree(backup_root, ignore_errors=True)
        return {"ok": False, "promoted": [], "rolled_back": True,
                "error": "%s: %s" % (type(e).__name__, e)}
    shutil.rmtree(backup_root, ignore_errors=True)
    return {"ok": True, "promoted": [rel for _, rel in staged], "rolled_back": False, "error": None}


def recover(staging_dir):
    p = Path(staging_dir)
    if p.exists():
        shutil.rmtree(p)
    return {"recovered": True, "path": str(p)}
