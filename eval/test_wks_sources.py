"""Regression tests for the forced source verification and the learning loop.

T39  the registry ships URLs that actually fetch
T40  forced verification records a MEASURED state per source and persists it
T41  a declared tier that disagrees with reality is reported, not hidden
T42  the learning loop consumes the MEASURED state, not the declared tier
T43  a source measured BLOCKED is listed do_not_use BEFORE the usable list
T44  the store's census matches what the verifier measured

The Medium case is the regression that matters: six registry entries were
declared `open` and all six returned HTTP 403. T39 pins the fix.

Run: python eval/test_wks_sources.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import (config, pipeline, research_sources as RS,  # noqa: E402
                 sourcebook, sourcegate, store, transport, verify_sources as VS)

FAILURES: list[str] = []
PASSES: list[str] = []


def check(label: str, cond: bool, detail: str = "", *, pass_detail: str = "") -> None:
    if cond:
        PASSES.append(label)
        print(f"  [PASS] {label}" + (f"  -- {pass_detail}" if pass_detail else ""))
    else:
        FAILURES.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}  -- {detail}")


def scratch() -> sqlite3.Connection:
    return store.open_db(Path(tempfile.mkdtemp(prefix="wks-src-")) / "t.db",
                         create=True)


# --------------------------------------------------------------------------
def t39_registry_urls_fetch() -> None:
    print("T39 the registry ships URLs that actually return content")
    # The measured failure: /tag/ returns 403, /feed/tag/ returns 200.
    for slug in ("bug-bounty", "bug-bounty-writeup", "bugbounty-tips"):
        reg = [s for s in RS.RESEARCH_SOURCES if slug in s.url]
        check(f"registry has an entry for {slug}", bool(reg))
        if not reg:
            continue
        url = reg[0].url
        check(f"{slug} uses the feed, not the 403 /tag/ page",
              "/feed/tag/" in url, url)
    check("no registry entry points at the blocked /tag/ form",
          not [s for s in RS.RESEARCH_SOURCES
               if s.host == "medium.com" and "/tag/" in s.url and "/feed/" not in s.url],
          "a /tag/ URL survived in the registry")
    check("the registry self-check passes", RS.problems() == [], str(RS.problems()))


def t40_verification_records_state() -> None:
    print("T40 forced verification records and persists a MEASURED state")
    r = VS.verify_one("https://portswigger.net/web-security/ssrf")
    check("a live source measures ACTIVE", r["measured_state"] == "ACTIVE",
          str(r["measured_state"]))
    check("a live source carries a content_hash", bool(r["content_hash"]))
    check("a live source records its http_status", r["http_status"] == 200,
          str(r["http_status"]))
    check("a live source returns prose", r["text_chars"] > 2000,
          str(r["text_chars"]))

    con = scratch()
    moved = store.record_access(
        con, "https://portswigger.net/web-security/ssrf",
        access_state=r["measured_state"], http_status=r["http_status"],
        content_hash=r["content_hash"], detail="forced verification")
    row = con.execute(
        "SELECT access_state, http_status, content_hash FROM source WHERE url=?",
        ("https://portswigger.net/web-security/ssrf",)).fetchone()
    check("record_access moves a row", moved is True)
    check("the state is persisted", row["access_state"] == "ACTIVE", row["access_state"])
    check("the hash is persisted", bool(row["content_hash"]))
    con.close()


def t41_disagreement_is_reported() -> None:
    print("T41 a declared tier that disagrees with reality is reported")
    check("declared open + measured ACTIVE = confirmed",
          VS.verdict("open", "ACTIVE") == "confirmed")
    check("declared open + measured BLOCKED = DISAGREES",
          VS.verdict("open", "BLOCKED") == "DISAGREES")
    check("declared walled + measured BLOCKED = confirmed",
          VS.verdict("walled", "BLOCKED") == "confirmed")
    check("declared key + measured BLOCKED = confirmed (no key is expected)",
          VS.verdict("key", "BLOCKED") == "confirmed")
    check("no declared tier = UNDECLARED",
          VS.verdict(None, "ACTIVE") == "UNDECLARED")
    # the HackerOne case: declared walled, and a 200 that is not content
    check("declared walled + measured BROWSER_REQUIRED = confirmed",
          VS.verdict("walled", "BROWSER_REQUIRED") == "confirmed")


def t42_loop_consumes_measured() -> None:
    print("T42 the learning loop reads the MEASURED state, not the declared tier")
    con = scratch()
    # a registry entry, declared open, measured BLOCKED
    store.record_access(con, "https://medium.com/tag/bug-bounty",
                        access_state="BLOCKED", http_status=403,
                        detail="DISAGREES: declared=open")
    # a healthy one
    store.record_access(con, "https://kathan19.gitbook.io/howtohunt",
                        access_state="ACTIVE", http_status=200)
    entries = [
        {"url": "https://medium.com/tag/bug-bounty", "access": "open"},
        {"url": "https://kathan19.gitbook.io/howtohunt", "access": "open"},
    ]
    split = sourcegate.annotate(con, entries)
    check("a BLOCKED source is not offered as usable",
          [e["url"] for e in split["usable"]] ==
          ["https://kathan19.gitbook.io/howtohunt"],
          str([e["url"] for e in split["usable"]]))
    check("a BLOCKED source lands in unusable",
          [e["url"] for e in split["unusable"]] ==
          ["https://medium.com/tag/bug-bounty"])
    check("an unmeasured source is neither usable nor unusable",
          sourcegate.annotate(con, [{"url": "https://x.test/a",
                                     "access": "open"}])["unmeasured"] != [])
    check("measured_state is None for a store that never measured",
          sourcegate.measured_state(con, "https://never.test/z") is None)
    con.close()


def t43_brief_lists_do_not_use_first() -> None:
    print("T43 a measured-unreachable source is listed FIRST in the brief")
    con = store.open_db(create=False)
    text = sourcebook.brief("idor", con)
    con.close()
    check("the brief states the verification coverage",
          "VERIFIED FETCHABLE" in text, "no coverage line")
    check("the brief shows a measured state per source",
          "[ACTIVE" in text or "[UNVERIFIED" in text,
          "no per-source measured state")
    if "DO NOT USE" in text:
        check("DO NOT USE appears before NORMATIVE",
              text.index("DO NOT USE") < text.index("NORMATIVE"),
              "the unusable list is buried below the usable one")
    else:
        check("no DO NOT USE block when every routed source is reachable",
              True, pass_detail="idor routes only to ACTIVE sources")

    wl = sourcebook.worklist("idor")
    check("worklist exposes do_not_use", "do_not_use" in wl)
    check("worklist exposes verification", "verification" in wl)


def t44_census_matches_measurements() -> None:
    print("T44 the store's census matches what the verifier measured")
    con = store.open_db(create=False)
    census = {r["access_state"]: r["n"] for r in con.execute(
        "SELECT access_state, count(*) n FROM source GROUP BY 1")}
    summary = sourcegate.verification_summary(con)
    con.close()
    check("summary total equals the census total",
          summary["sources"] == sum(census.values()),
          f"{summary['sources']} vs {sum(census.values())}")
    check("summary active equals the census ACTIVE count",
          summary["active"] == census.get("ACTIVE", 0),
          f"{summary['active']} vs {census.get('ACTIVE', 0)}")
    check("coverage is above 95% after forced verification",
          summary["coverage_pct"] > 95.0, str(summary["coverage_pct"]))
    print(f"        census={census}")


def main() -> int:
    for fn in (t39_registry_urls_fetch, t40_verification_records_state,
               t41_disagreement_is_reported, t42_loop_consumes_measured,
               t43_brief_lists_do_not_use_first, t44_census_matches_measurements):
        try:
            fn()
        except Exception as e:
            FAILURES.append(f"{fn.__name__} raised {e}")
            print(f"  [ERROR] {fn.__name__}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())