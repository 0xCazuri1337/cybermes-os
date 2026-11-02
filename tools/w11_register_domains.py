#!/usr/bin/env python
"""Register class_domain rows for classes that have none.

WHY: measured 2026-10-03 — `otp`, `rate_limit` and `eol_software` are
registered in `bug_class` but hold ZERO rows in `class_domain`, so
`wks.cli domains --check` reports them as missing and the architecture
auditor (masterprompt check c_54 / §54) fails.

TRAPS this script exists to avoid:
  1. `class_domain.specialization` is NOT NULL. Passing explicit NULL violates
     it, `INSERT OR IGNORE` swallows the violation, and the run prints
     "registered" for every class while writing ZERO rows. Assert rowcount.
  2. `INSERT OR IGNORE` reporting success while inserting nothing is still live
     in this codebase. A plain INSERT raises instead of vanishing -- but then a
     re-run raises on the PK, so: try INSERT, fall back to UPDATE, then assert
     the row is readable back.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import config as wks_config  # noqa: E402
from wks import domains as wks_domains  # noqa: E402

# class_id -> expected domain. NEVER hand-write a domain string: `domain_of()`
# only accepts WEB/NETWORK, and a class_domain row naming anything else (e.g.
# "identity", "infrastructure") is silently IGNORED, so the row looks
# registered while the checker keeps resolving the class through its surface.
# MEASURED 2026-10-03: I wrote "identity"/"infrastructure" and `domains --check`
# still reported 3 missing pages naming `domains/web/...`.
#
# So: assert the expected domain against `domains.domain_of()` itself, and let
# the surface decide. These two surfaces both route to WEB.
REGISTRATIONS: dict[str, tuple[str, str]] = {
    "otp": (wks_domains.WEB, "-"),
    "rate_limit": (wks_domains.WEB, "-"),
    "eol_software": (wks_domains.WEB, "-"),
}


def main() -> int:
    root = os.environ.get("WKS_ROOT") or str(wks_config.WKS_ROOT)
    db = Path(root) / "db" / "wks.db"
    if not db.exists():
        print(f"FATAL: no database at {db}")
        return 2
    con = sqlite3.connect(str(db))
    now = datetime.now(timezone.utc).isoformat()
    failures = 0

    for class_id, (domain, spec) in REGISTRATIONS.items():
        exists = con.execute(
            "SELECT 1 FROM bug_class WHERE id=?", (class_id,)
        ).fetchone()
        if not exists:
            print(f"  SKIP  {class_id}: not in bug_class (register it first)")
            failures += 1
            continue

        before = con.execute(
            "SELECT domain, specialization FROM class_domain WHERE class_id=?",
            (class_id,),
        ).fetchone()
        if before and before[0] not in wks_domains.DOMAIN_LABEL:
            print(f"  FIX   {class_id}: stale domain {before[0]!r} is not one of "
                  f"{sorted(wks_domains.DOMAIN_LABEL)} and was being ignored")

        # The assertion that would have caught the original bug: what domain
        # does the RESOLVER actually reach for this class? If that disagrees with
        # the domain we are about to write, the row is decoration, not routing.
        resolver = sqlite3.connect(str(db))
        resolver.row_factory = sqlite3.Row
        try:
            resolved = wks_domains.domain_of(resolver, class_id)
        except KeyError as exc:
            print(f"  FAIL  {class_id}: domain_of() raised: {exc}")
            failures += 1
            continue
        finally:
            resolver.close()
        if resolved != domain:
            print(f"  FAIL  {class_id}: resolver reaches {resolved!r} but we would "
                  f"write {domain!r}; the row would be ignored")
            failures += 1
            continue

        if before is None:
            try:
                # Plain INSERT: a constraint violation must RAISE, not vanish.
                con.execute(
                    "INSERT INTO class_domain(class_id, domain, specialization,"
                    " updated_at) VALUES (?,?,?,?)",
                    (class_id, domain, spec, now),
                )
                action = "inserted"
            except sqlite3.IntegrityError:
                action = "insert-ignored"
        else:
            con.execute(
                "UPDATE class_domain SET domain=?, specialization=?, updated_at=?"
                " WHERE class_id=?",
                (domain, spec, now, class_id),
            )
            action = "updated"

        con.commit()

        # ALWAYS read the row back -- never trust the action string.
        after = con.execute(
            "SELECT domain, specialization FROM class_domain WHERE class_id=?",
            (class_id,),
        ).fetchone()
        if after is None:
            print(f"  FAIL  {class_id}: {action} but the row is NOT readable back")
            failures += 1
        elif after[0] != domain or after[1] != spec:
            print(f"  FAIL  {class_id}: {action} but reads back {after}")
            failures += 1
        else:
            print(f"  ok    {class_id}: {action} -> domain={after[0]!r} "
                  f"specialization={after[1]!r}")

    total = con.execute("SELECT COUNT(*) FROM class_domain").fetchone()[0]
    print(f"class_domain rows now: {total}")
    con.close()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
