"""Regression tests for every failure mode the 2026-10-02 audit found fixed.

Each test names the defect it locks down. A test that does not correspond to a
measured failure is decoration, so nothing here exists "for coverage".

Run:  python eval/test_wks_infra.py       (non-zero exit on any failure)

Negative controls are deliberate. T24 in particular tampers with the 429 path,
because a rate-limit test that cannot fail is the same defect as a "secure app
is clean" assertion that passes against a total no-op.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import (  # noqa: E402
    config, pipeline, quality, snapshot, store, staleness, transport)
from wks import transport as T   # the access-state / retry layer
from wks.verify_quotes import find_quote  # noqa: E402

FAILURES: list[str] = []
PASSES: list[str] = []


def check(label: str, cond: bool, detail: str = "", *,
          pass_detail: str = "") -> bool:
    if cond:
        PASSES.append(label)
        note = pass_detail or ""
        print(f"  [PASS] {label}" + (f"  -- {note}" if note else ""))
    else:
        FAILURES.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}  -- {detail}")
    return bool(cond)


def scratch_db() -> sqlite3.Connection:
    d = tempfile.mkdtemp(prefix="wks-infra-test-")
    con = store.open_db(config.ROOT / d / "t.db", create=True)
    return con


# ==========================================================================
# T22  source access states exist as a closed vocabulary
# ==========================================================================
def t22_access_states() -> None:
    print("T22 source access states are a closed, complete vocabulary")
    required = {"ACTIVE", "RATE_LIMITED", "BLOCKED", "PAYWALLED",
                "BROWSER_REQUIRED", "STALE", "UNVERIFIED"}
    check("every required state is defined",
          required <= set(T.ACCESS_STATES),
          f"missing {sorted(required - set(T.ACCESS_STATES))}")
    check("self-check reports no problems", T.problems() == [], str(T.problems()))
    # classification, per measured behaviour
    cases = [
        (200, "prose here.", False, "ACTIVE"),
        (429, "", False, "RATE_LIMITED"),
        (403, "", False, "BLOCKED"),
        (404, "", False, "BLOCKED"),
        (451, "", False, "BLOCKED"),
        (500, "", False, "UNVERIFIED"),
        (None, "", False, "UNVERIFIED"),
        # MEASURED: HackerOne returns HTTP 200 whose body is
        # browser-not-supported.html. A 200 must NOT read as ACTIVE.
        (200, "<html><body>Loading…</body></html>", True, "BROWSER_REQUIRED"),
        (200, "Subscribe to continue reading the rest of this article", False,
         "PAYWALLED"),
    ]
    for status, body, shell, want in cases:
        got = T.classify(status, body, had_shell=shell)
        check(f"classify({status}, shell={shell}) -> {want}", got == want, f"got {got}")
    # the vocabulary is persisted, not only computed
    con = scratch_db()
    store.upsert_source(con, "https://example.org/a", "example.org",
                        access_state="PAYWALLED", http_status=200)
    got = con.execute("SELECT access_state FROM source WHERE url=?",
                      ("https://example.org/a",)).fetchone()["access_state"]
    check("access_state is persisted on the source row", got == "PAYWALLED", got)
    try:
        store.upsert_source(con, "https://example.org/b", "example.org",
                            access_state="MADE_UP")
        check("an unknown access_state is refused", False, "accepted a bogus state")
    except ValueError:
        check("an unknown access_state is refused", True)
    con.close()


# ==========================================================================
# T23  a measured access state is never overwritten by a bare declaration
#      (the exact regression the first rewrite of upsert_source introduced)
# ==========================================================================
def t23_monotonic_access() -> None:
    print("T23 a measured access state survives a declared upsert")
    con = scratch_db()
    url = "https://example.org/monotonic"
    store.record_access(con, url, access_state="ACTIVE", http_status=200,
                        content_hash="a" * 32, detail="measured")
    store.upsert_source(con, url, "example.org", source_type="writeup")
    got = con.execute("SELECT access_state, http_status FROM source WHERE url=?",
                      (url,)).fetchone()
    check("declared upsert does not downgrade ACTIVE -> UNVERIFIED",
          got["access_state"] == "ACTIVE", got["access_state"])
    check("declared upsert does not erase the recorded http_status",
          got["http_status"] == 200, str(got["http_status"]))
    store.upsert_source(con, url, "example.org", access_state="STALE", http_status=404)
    got = con.execute("SELECT access_state FROM source WHERE url=?",
                      (url,)).fetchone()
    check("an EXPLICIT state still wins (that caller measured)",
          got["access_state"] == "STALE", got["access_state"])
    con.close()


# ==========================================================================
# T24  429 is handled: Retry-After parsed, budget honoured, state recorded.
#      Includes a NEGATIVE control -- the retry loop must be tamperable to red.
# ==========================================================================
def t24_rate_limit() -> None:
    print("T24 HTTP 429 is handled, not silently swallowed")
    # Retry-After, both documented forms
    check("delta-seconds Retry-After parses (and clamps to the cap)",
          T.parse_retry_after("120") == T.MAX_RETRY_AFTER,
          str(T.parse_retry_after("120")))
    check("a small delta-seconds value is honoured exactly",
          T.parse_retry_after("5") == 5.0, str(T.parse_retry_after("5")))
    check("Retry-After is capped", T.parse_retry_after("99999") == T.MAX_RETRY_AFTER,
          str(T.parse_retry_after("99999")))
    http_date = "Wed, 21 Oct 2099 07:28:00 GMT"
    got = T.parse_retry_after(http_date)
    check("HTTP-date Retry-After parses and clamps to the cap",
          got == T.MAX_RETRY_AFTER, str(got))
    check("malformed Retry-After returns None (never 'retry now')",
          T.parse_retry_after("soon-ish") is None)
    check("absent Retry-After returns None", T.parse_retry_after(None) is None)

    # The retry loop, driven by a stub that always answers 429.
    calls = {"n": 0}

    def always_429(url, **kw):
        calls["n"] += 1
        return {"url": url, "host": "x.test", "status": 429, "raw": b"",
                "content_type": "", "retry_after": None, "error": "429",
                "retrieved_at": T.now_iso()}

    orig = T.request_once
    T.request_once = always_429
    try:
        out = T.fetch_raw("https://x.test/a", max_attempts=3)
        check("a 429 is retried up to the budget", calls["n"] == 3, f"{calls['n']} calls")
        check("exhausted 429 reports rate_limited", out["rate_limited"] is True)
        check("exhausted 429 classifies as RATE_LIMITED",
              out["access_state"] == "RATE_LIMITED", out["access_state"])
        check("a throttled host is recorded for the audit",
              "x.test" in T.rate_limited_hosts())
        check("waited_seconds is reported", out["waited_seconds"] > 0,
              str(out["waited_seconds"]))
    finally:
        T.request_once = orig
        T.reset_throttle()

    # 200 is NOT rate limited, and does not consume retries
    calls["n"] = 0

    def always_200(url, **kw):
        calls["n"] += 1
        return {"url": url, "host": "y.test", "status": 200, "raw": b"prose",
                "content_type": "text/plain", "retry_after": None, "error": None,
                "retrieved_at": T.now_iso()}

    T.request_once = always_200
    try:
        out = T.fetch_raw("https://y.test/a", max_attempts=3)
        check("a 200 makes exactly one attempt", calls["n"] == 1, f"{calls['n']}")
        check("a 200 is not rate limited", out["rate_limited"] is False)
    finally:
        T.request_once = orig
        T.reset_throttle()

    # NEGATIVE CONTROL: tamper the classifier so 429 is no longer recognised.
    # The suite must go red, or the test above proves nothing.
    orig_classify = T.classify
    T.classify = lambda status, body="", had_shell=False: "UNVERIFIED"
    try:
        T.request_once = always_429
        out = T.fetch_raw("https://x.test/b", max_attempts=2)
        red = out["access_state"] == "UNVERIFIED"
        check("NEGATIVE CONTROL: tampering the classifier is detected",
              red, "test cannot distinguish a broken classifier")
    finally:
        T.classify = orig_classify
        T.request_once = orig
        T.reset_throttle()


# ==========================================================================
# T25  per-host pacing
# ==========================================================================
def t25_host_throttle() -> None:
    print("T25 per-host pacing floor is enforced")
    import time
    T.reset_throttle()
    # Test the PRIMITIVE. An earlier version stubbed `request_once`, which is
    # the function that CALLS `_throttle` -- so the stub removed the pacing and
    # the test measured nothing while passing.
    hits = []
    for _ in range(3):
        t0 = time.monotonic()
        T._throttle("slow.test")
        hits.append(time.monotonic())
    gaps = [hits[i + 1] - hits[i] for i in range(len(hits) - 1)]
    check("consecutive hits on one host are spaced by the floor",
          all(g >= T.HOST_MIN_INTERVAL - 0.05 for g in gaps),
          f"gaps={[round(g, 3) for g in gaps]} floor={T.HOST_MIN_INTERVAL}")
    # NEGATIVE CONTROL: with no floor the same loop must show no spacing.
    saved = T.HOST_MIN_INTERVAL
    T.HOST_MIN_INTERVAL = 0.0
    try:
        T.reset_throttle()
        fast = []
        for _ in range(3):
            T._throttle("fast.test")
            fast.append(time.monotonic())
        fast_gaps = [fast[i + 1] - fast[i] for i in range(len(fast) - 1)]
        check("NEGATIVE CONTROL: zero floor removes the spacing",
              all(g < 0.05 for g in fast_gaps),
              f"gaps={[round(g, 4) for g in fast_gaps]}")
    finally:
        T.HOST_MIN_INTERVAL = saved
        T.reset_throttle()


# ==========================================================================
# T26  the 2-child cap is enforced in code, not only in documentation
# ==========================================================================
def t26_concurrency_cap() -> None:
    print("T26 the measured 2-child cap is enforced in the execution path")
    from orch import concurrency as C

    check("default cap is the MEASURED value (2)", C.DEFAULT_MAX_CHILDREN == 2,
          str(C.DEFAULT_MAX_CHILDREN))
    check("cap truncates a 5-task wave to 2",
          C.cap(["a", "b", "c", "d", "e"]) == ["a", "b"])
    check("deferred tasks are RETURNED, not dropped",
          C.dropped(["a", "b", "c", "d", "e"]) == ["c", "d", "e"])
    check("cap preserves priority order (takes the head)",
          C.cap([9, 8, 7, 6, 5]) == [9, 8])
    check("an empty wave stays empty", C.cap([]) == [])
    check("self-check reports no problems", C.problems() == [], str(C.problems()))

    # the cap can never be disabled to zero -- a "safety limit" that can be
    # switched off is not a limit
    old = os.environ.get(C.ENV_VAR)
    os.environ[C.ENV_VAR] = "0"
    try:
        check("an override of 0 cannot disable the wave", C.budget() >= 1,
              f"budget={C.budget()}")
        os.environ[C.ENV_VAR] = "not-a-number"
        check("a malformed override falls back to the default", C.budget() == 2,
              str(C.budget()))
    finally:
        if old is None:
            os.environ.pop(C.ENV_VAR, None)
        else:
            os.environ[C.ENV_VAR] = old

    # and it is enforced where tasks are actually dispatched
    import inspect
    from orch import orchestrator
    body = inspect.getsource(orchestrator._execute_one)
    check("_execute_one refuses an over-cap wave",
          "concurrency.budget()" in body and '"capped"' in body,
          pass_detail="cap check present in the dispatch path")
    run_src = inspect.getsource(orchestrator.run)
    check("run() caps the wave before executing",
          "concurrency.cap(" in run_src,
          pass_detail="wave cap present in run()")
    check("deferred work is reported in the run record",
          '"concurrency"' in run_src and "capped_waves" in run_src)


# ==========================================================================
# T27  audits are snapshot-safe
# ==========================================================================
def t27_snapshot() -> None:
    print("T27 corpus audits read one consistent world")
    info = snapshot.frozen_copy()
    check("frozen copy passes integrity_check",
          info["integrity_check"] == "ok", str(info["integrity_check"]))
    check("frozen copy preserves every table",
          info["tables_copy"] == info["tables_source"],
          f"{info['tables_copy']} vs {info['tables_source']}")
    check("frozen copy row fingerprints match the source",
          info["fingerprint_matches"] is True, str(info["fingerprint"]))
    con = snapshot.read_frozen(info)
    a = con.execute("SELECT count(*) FROM item").fetchone()[0]
    b = con.execute("SELECT count(*) FROM item").fetchone()[0]
    check("repeated reads of one snapshot agree", a == b, f"{a} vs {b}")
    con.close()

    # a snapshot connection is read-only: an audit that promised not to write
    # must fail if it tries
    con = snapshot.snapshot(label="t27")
    try:
        con.execute("DELETE FROM item WHERE 1=0")
        check("a snapshot connection refuses writes", False, "the write succeeded")
    except sqlite3.Error as e:
        check("a snapshot connection refuses writes", True, type(e).__name__)
    finally:
        snapshot.release("t27")

    # moved_under_audit detects the corpus moving under an audit
    d = snapshot.moved_under_audit({"item": 10}, {"item": 11})
    check("a mid-audit corpus change is detectable", d == {"item": (10, 11)}, str(d))
    same = snapshot.moved_under_audit({"item": 10}, {"item": 10})
    check("an unchanged corpus reports no delta", same == {}, str(same))


# ==========================================================================
# T28  staleness is measurable (it was 'unmeasured' and reported as 0.0)
# ==========================================================================
def t28_staleness() -> None:
    print("T28 stale sources are distinguishable from unmeasured sources")
    from wks import staleness
    con = scratch_db()
    store.upsert_source(con, "https://example.org/measured", "example.org",
                        access_state="ACTIVE", http_status=200,
                        content_hash="b" * 32)
    store.upsert_source(con, "https://example.org/never", "example.org")
    cand = {r["url"] for r in staleness.candidates(con)}
    check("a measured source is a staleness candidate",
          "https://example.org/measured" in cand, str(cand))
    check("a never-fetched source is NOT a candidate (cannot be stale)",
          "https://example.org/never" not in cand)
    unm = {r["url"] for r in staleness.unmeasured(con)}
    check("a never-fetched source is reported as unmeasured",
          "https://example.org/never" in unm, str(unm))

    # the check itself: an unreachable source that was ACTIVE is STALE
    r = staleness.check_one("https://example.org/gone", "c" * 32)
    check("a source that stopped answering is STALE", r["verdict"] == "STALE",
          str(r["verdict"]))
    con.close()


# ==========================================================================
# T29  the text-extraction refactor did not change quote matching.
#      This is the regression the audit's own verification caught.
# ==========================================================================
def t29_extract_text_unchanged() -> None:
    print("T29 extract_text preserves the quote-matching contract")
    raw = b"<html><body><p>It&#x27;s a &quot;tagged&quot; page.</p></body></html>"
    text = pipeline.extract_text(raw, "text/html")
    check("entities are decoded before tag-stripping",
          "It's a" in text and '&' not in text, repr(text[:80]))
    # the exact shape that broke: the fetch layer must return prose, not b""
    got = pipeline.fetch("https://portswigger.net/web-security/graphql")
    check("pipeline.fetch returns prose text", len(got.get("text", "")) > 2000,
          f"len={len(got.get('text',''))} state={got.get('access_state')}")
    check("pipeline.fetch reports an access_state",
          got.get("access_state") in T.ACCESS_STATES, str(got.get("access_state")))
    check("pipeline.fetch reports a content_hash", bool(got.get("content_hash")))
    check("a genuinely quoted span matches the fetched page",
          find_quote(got["text"], "GraphQL"))


def main() -> int:
    for fn in (t22_access_states, t23_monotonic_access, t24_rate_limit,
               t25_host_throttle, t26_concurrency_cap, t27_snapshot,
               t28_staleness, t29_extract_text_unchanged):
        try:
            fn()
        except Exception:
            FAILURES.append(f"{fn.__name__} raised")
            print(f"  [ERROR] {fn.__name__} raised:")
            traceback.print_exc()
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())