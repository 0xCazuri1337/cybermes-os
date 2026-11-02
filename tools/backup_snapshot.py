"""Takes a RESTORABLE, VERIFIED snapshot of the project and its databases.

WHY THIS EXISTS
===============
MEASURED 2026-11-02: every backup in this project had been taken ad hoc --
a `tar` here, a `cp` of the database there -- with no manifest, no checksums,
and no proof that the result could be restored. The archives under
`cyber-archives/` contain `snapshot.tar.gz` and a four-line manifest whose
`entries`/`files` counts cannot be checked against anything, and the SQLite
copies were made with `cp` on a database in WAL mode, which can capture a
torn state.

The mission's backup rule is specific: include code, configuration,
documentation, project data and databases; use a CONSISTENT SQLite backup
mechanism; generate a manifest with paths, sizes and checksums; and VERIFY
that the backup can be inspected and restored.

WHAT THIS DOES
==============
  * The project tree is archived with `tar`, excluding the archive
    directory itself, transient caches and `__pycache__`.
  * Every SQLite database is copied through sqlite's ONLINE BACKUP API --
    never `cp` -- so a WAL database is captured whole and consistently.
    The copy is verified with `PRAGMA integrity_check` and a table count.
  * A manifest records, for every archived file and every database copy:
    path, size and sha256.
  * The archive is verified by LISTING it and by EXTRACTING it to a
    temporary directory, where the extracted tree is checked against the
    manifest's file count and the extracted databases are re-checked with
    `PRAGMA integrity_check`.

Nothing is deleted. The destination directory is created fresh and never
overwrites an existing snapshot: the timestamp is second-resolution, and the
refusal is explicit rather than a silent overwrite.

Usage:
    python tools/backup_snapshot.py --label provenance-closure
    python tools/backup_snapshot.py --label x --root /path/to/project
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ROOT = Path("/mnt/c/Users/Administrator/.hermes/cyber")
DEFAULT_ARCHIVES = Path("/mnt/c/Users/Administrator/.hermes/cyber-archives")

# Directories never worth archiving: transient, regenerable, or huge.
EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", ".git",
}
EXCLUDE_SUFFIX = (".pyc", ".pyo")

# SQLite extensions that are worth a CONSISTENT copy.
DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n}B"


def sqlite_consistent_copy(src: Path, dest: Path) -> dict:
    """Copy a SQLite database through the online backup API and verify it.

    `cp` is not used: the database runs in WAL mode, so the `.db` file
    without its `-wal` is not the database, and a copy taken while a writer
    is active can tear. `sqlite3.Connection.backup` produces a consistent,
    self-contained file.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    scon = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    try:
        tables_src = scon.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        dcon = sqlite3.connect(dest)
        try:
            with dcon:
                scon.backup(dcon)
        finally:
            dcon.close()
    finally:
        scon.close()
    chk = sqlite3.connect(f"file:{dest}?mode=ro", uri=True)
    try:
        integrity = chk.execute("PRAGMA integrity_check").fetchone()[0]
        tables_dst = chk.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    finally:
        chk.close()
    return {
        "source": str(src),
        "copy": str(dest),
        "integrity": integrity,
        "tables_source": tables_src,
        "tables_copy": tables_dst,
        "bytes": dest.stat().st_size,
        "sha256": sha256_file(dest),
        "consistent": integrity == "ok" and tables_src == tables_dst,
    }


def iter_project_files(root: Path):
    """Every file under `root` that belongs in the snapshot."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for name in filenames:
            if name.endswith(EXCLUDE_SUFFIX):
                continue
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            yield p


def take_snapshot(root: Path, archives: Path, label: str) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"cyber-{label}-{stamp}"
    dest = archives / name
    if dest.exists():
        raise SystemExit(f"refusing to overwrite an existing snapshot: {dest}")
    dest.mkdir(parents=True)

    # ---- 1. consistent database copies -----------------------------------
    #
    # THE COPIES GO INSIDE THE ARCHIVE.
    #
    # MEASURED 2026-11-02: the first implementation wrote the consistent
    # database copies to a `databases/` directory BESIDE the archive, and
    # the restore verification then looked for them inside the extracted
    # tree -- where they were not. Every database reported "missing" and
    # the snapshot reported `verified: false`, because the verification
    # was checking a place the copies had never been put.
    #
    # The copies are now staged under `databases/` INSIDE the archive, so
    # extracting the archive restores both the project tree AND the
    # consistent database copies, and the verification reads what the
    # archive actually contains.
    dbs: list[dict] = []
    stage = dest / "stage" / "databases"
    for p in sorted(iter_project_files(root)):
        if p.suffix not in DB_SUFFIXES:
            continue
        rel = p.relative_to(root)
        try:
            info = sqlite_consistent_copy(p, stage / rel)
        except sqlite3.Error as exc:
            dbs.append({"source": str(rel), "error": str(exc),
                        "consistent": False})
            continue
        info["source"] = str(rel)
        info["copy"] = f"databases/{rel.as_posix()}"
        dbs.append(info)

    # ---- 2. the project tree ---------------------------------------------
    tar_path = dest / "snapshot.tar.gz"
    files: list[dict] = []
    with tarfile.open(tar_path, "w:gz") as tf:
        for p in sorted(iter_project_files(root)):
            rel = p.relative_to(root)
            # The canonical database and its siblings are archived as the
            # consistent copies above; the raw file is archived too, because
            # "nothing is deleted" means the original bytes are retained.
            tf.add(p, arcname=str(rel), recursive=False)
            files.append({"path": str(rel), "bytes": p.stat().st_size})
        # The consistent database copies, under `databases/`.
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                tf.add(p, arcname=str(Path("databases") /
                                      p.relative_to(stage)),
                       recursive=False)

    # ---- 3. checksums ----------------------------------------------------
    for rec in files:
        rec["sha256"] = sha256_file(root / rec["path"])

    # ---- 4. verify: the archive lists and extracts ------------------------
    with tarfile.open(tar_path, "r:gz") as tf:
        archived = [m for m in tf.getmembers() if m.isfile()]
    verify_tmp = Path(tempfile.mkdtemp(prefix="cyber-restore-verify-"))
    try:
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extractall(verify_tmp, filter="data")
        extracted_files = sorted(
            str(p.relative_to(verify_tmp)) for p in verify_tmp.rglob("*")
            if p.is_file())
        archived_paths = sorted(
            str(Path(m.name).as_posix()) for m in archived)
        restore_match = extracted_files == archived_paths
        # Re-check every extracted database, at the path the archive holds
        # it -- not at a path it was never written to.
        db_restore: list[dict] = []
        for rec in dbs:
            if "error" in rec:
                continue
            restored = verify_tmp / rec["copy"]
            integrity = "missing"
            tables = -1
            if restored.exists():
                c = sqlite3.connect(f"file:{restored}?mode=ro", uri=True)
                try:
                    integrity = c.execute(
                        "PRAGMA integrity_check").fetchone()[0]
                    tables = c.execute(
                        "SELECT count(*) FROM sqlite_master WHERE type='table'"
                    ).fetchone()[0]
                finally:
                    c.close()
            db_restore.append({
                "copy": rec["copy"],
                "integrity": integrity,
                "tables": tables,
                "ok": (integrity == "ok"
                       and tables == rec.get("tables_copy", -1)),
            })
    finally:
        shutil.rmtree(verify_tmp, ignore_errors=True)

    manifest = {
        "snapshot": name,
        "created": stamp,
        "root": str(root),
        "archive": str(tar_path),
        "archive_bytes": tar_path.stat().st_size,
        "archive_sha256": sha256_file(tar_path),
        "file_count": len(files),
        "files": files,
        "databases": dbs,
        "restore_verification": {
            "archived_members": len(archived),
            "extracted_files": len(extracted_files),
            "listing_matches_manifest": (
                sorted(f["path"] for f in files)
                == [p for p in archived_paths
                    if not p.startswith("databases/")]),
            "extract_matches_archive": restore_match,
            "databases": db_restore,
        },
        "verified": (
            # Every project file AND every consistent database copy is in
            # the archive, and the archive extracts to exactly what it
            # listed.
            #
            # MEASURED 2026-11-02: the member count compared the archive's
            # FILE count against `len(files) + len(db_restore)`, which is
            # the count of DATABASES -- not of files. SQLite's online
            # backup API leaves `-wal` and `-shm` sidecars beside each
            # copy, and those are archived too, so 31 databases became 87
            # archive members. The count was therefore wrong by 56 and
            # EVERY snapshot reported `verified: false` even though every
            # file was present and every database restored cleanly.
            #
            # The check is now on the thing it means: every project file
            # and every database COPY is present, and the extracted tree
            # matches the archive exactly.
            len(archived) >= len(files) + len(db_restore)
            and all(f["path"] in archived_paths for f in files)
            and all(d["copy"] in archived_paths for d in db_restore)
            and sorted(f["path"] for f in files)
            == [p for p in archived_paths
                if not p.startswith("databases/")]
            and restore_match
            and all(d.get("consistent") for d in dbs if "error" not in d)
            and all(d["ok"] for d in db_restore)
        ),
        "note": ("Databases are copied through sqlite's online backup API "
                 "(never cp) because the store runs in WAL mode, and the "
                 "copies live INSIDE the archive under databases/. The "
                 "archive was listed AND extracted to a temporary directory "
                 "to prove it can be restored."),
    }
    (dest / "manifest.json").write_text(
        json.dumps(manifest, indent=1, default=str), encoding="utf-8")
    # The staging tree has served its purpose: the copies now live inside
    # the archive, and the archive is the deliverable.
    shutil.rmtree(dest / "stage", ignore_errors=True)
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    ap.add_argument("--archives", default=str(DEFAULT_ARCHIVES))
    ap.add_argument("--label", default="snapshot")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    archives = Path(args.archives).resolve()
    archives.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    m = take_snapshot(root, archives, args.label)
    print(json.dumps({
        "snapshot": m["snapshot"],
        "archive": m["archive"],
        "archive_bytes": m["archive_bytes"],
        "file_count": m["file_count"],
        "databases": len(m["databases"]),
        "verified": m["verified"],
        "elapsed_s": round(time.time() - t0, 1),
    }, indent=1))
    return 0 if m["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
