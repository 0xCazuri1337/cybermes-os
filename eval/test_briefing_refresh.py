"""Regression test for the agent-briefing refresh.

MEASURED 2026-10-31: the `/update` command spec's stage (g) says

    Update timestamp + knowledge count in agent-briefing.md -- static
    sections PRESERVED, never overwritten.

and `AGENTS.md` §11 says the same. No code did it. The briefing's
"Last updated" line read 2026-10-29 while the corpus under it was being
regenerated, and nothing compared the two.

The property that matters here is NEGATIVE: the refresh must change the
GENERATED header and must NOT change the hand-maintained body. A refresh
that rewrites the whole file is a data-loss bug dressed as a feature, so
these checks assert on what was PRESERVED, not only on what changed.

The test runs against a SANDBOX copy of the briefing and a sandboxed
database. The canonical briefing is never written.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

PASSES: list[str] = []
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSES.append(label)
        print(f"  [PASS] {label}")
    else:
        FAILURES.append(f"{label} -- {detail}")
        print(f"  [FAIL] {label}  {detail}")


def sandbox():
    """A sandbox copy of the briefing, with the module pointed at it."""
    sb = Path(tempfile.mkdtemp(prefix="briefing_test_"))
    shutil.copy2(REPO / "agent-briefing.md", sb / "agent-briefing.md")
    (sb / "runtime").mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / "runtime" / "registry.json", sb / "runtime" / "registry.json")
    for mod in list(sys.modules):
        if mod.startswith("writeups"):
            del sys.modules[mod]
    sys.path.insert(0, str(sb))
    import writeups.briefing as briefing
    # Point the module at the sandbox copy.
    briefing.BRIEFING = sb / "agent-briefing.md"
    return sb, briefing


def t01_report_only_writes_nothing() -> None:
    print("T01 report-only mode writes nothing")
    sb, B = sandbox()
    try:
        before = B.BRIEFING.read_text(encoding="utf-8")
        out = B.refresh(apply=False)
        after = B.BRIEFING.read_text(encoding="utf-8")
        check("report-only leaves the file byte-identical", before == after)
        check("report-only still reports whether it would change",
              "changed" in out, str(out)[:120])
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t02_static_body_is_preserved() -> None:
    print("T02 the static sections are preserved, byte for byte")
    sb, B = sandbox()
    try:
        before = B.BRIEFING.read_text(encoding="utf-8")
        B.refresh(apply=True)
        after = B.BRIEFING.read_text(encoding="utf-8")

        # Every non-generated line must survive.
        gen_markers = ("Last updated:", "Knowledge base:")
        before_static = [ln for ln in before.splitlines()
                         if not ln.startswith(gen_markers)]
        after_static = [ln for ln in after.splitlines()
                        if not ln.startswith(gen_markers)]
        check("every static line survives unchanged",
              before_static == after_static,
              "the static body was modified")
        for section in ("## HEADER & OPERATING IDENTITY", "## MISSION",
                        "## STARTUP DISCIPLINE"):
            check(f"the {section!r} section survives",
                  section in after, "missing")
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t03_header_is_refreshed() -> None:
    print("T03 the generated header is refreshed")
    sb, B = sandbox()
    try:
        B.refresh(apply=True)
        text = B.BRIEFING.read_text(encoding="utf-8")
        check("the timestamp line is present", "Last updated:" in text)
        check("the knowledge line carries the item count",
              "items" in text and "lessons" in text, text[:400])
        check("the knowledge line names the source of truth",
              "WKS domains" in text, text[:400])
        # The refreshed timestamp must not be the stale one.
        import re
        stamp = re.search(r"^Last updated: (\S+)", text, re.M)
        check("the timestamp is parseable", stamp is not None, text[:200])
        if stamp:
            check("the timestamp is today's UTC date",
                  stamp.group(1) == __import__("datetime").datetime.now(
                      __import__("datetime").timezone.utc).strftime("%Y-%m-%d"),
                  stamp.group(1))
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t04_bias_block_is_regenerated() -> None:
    print("T04 the bias block is regenerated inside its markers")
    sb, B = sandbox()
    try:
        text = B.BRIEFING.read_text(encoding="utf-8")
        if "<!-- BEGIN BIASES -->" not in text:
            check("the briefing has bias markers", False,
                  "the markers are missing, so the block cannot be regenerated")
            return
        B.refresh(apply=True)
        after = B.BRIEFING.read_text(encoding="utf-8")
        check("the markers survive", "<!-- BEGIN BIASES -->" in after
              and "<!-- END BIASES -->" in after)
        start = after.index("<!-- BEGIN BIASES -->")
        end = after.index("<!-- END BIASES -->")
        block = after[start:end]
        check("the block is non-empty", len(block) > 40, block[:80])
        check("the block names its sources",
              "report-lessons" in block or "patterns" in block, block[:200])
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t05_no_store_means_no_write() -> None:
    print("T05 an unavailable store means NO write, not a write of zeros")
    sb, B = sandbox()
    try:
        before = B.BRIEFING.read_text(encoding="utf-8")
        original = B.knowledge_counts

        def broken():
            return {"ok": False, "reason": "canonical store unavailable: test"}

        B.knowledge_counts = broken
        out = B.refresh(apply=True)
        after = B.BRIEFING.read_text(encoding="utf-8")
        B.knowledge_counts = original

        check("the refresh reports the failure", not out.get("ok"), str(out)[:120])
        check("the file was NOT touched", before == after,
              "a briefing claiming zero lessons was written")
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t06_refresh_is_idempotent() -> None:
    print("T06 a second refresh changes nothing further")
    sb, B = sandbox()
    try:
        B.refresh(apply=True)
        first = B.BRIEFING.read_text(encoding="utf-8")
        out = B.refresh(apply=True)
        second = B.BRIEFING.read_text(encoding="utf-8")
        check("the second refresh is a no-op", first == second,
              "the briefing changed on a second refresh")
        check("the second refresh reports no change",
              out.get("changed") is False, str(out)[:120])
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def main() -> int:
    for fn in (t01_report_only_writes_nothing,
               t02_static_body_is_preserved,
               t03_header_is_refreshed,
               t04_bias_block_is_regenerated,
               t05_no_store_means_no_write,
               t06_refresh_is_idempotent):
        try:
            fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            FAILURES.append(f"{fn.__name__} raised {type(e).__name__}: {e}")
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    print("BRIEFING REFRESH: ALL CHECKS PASS" if not FAILURES
          else "BRIEFING REFRESH: FAILURES ABOVE")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
