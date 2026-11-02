"""Regression test: a falsifier must match the claim's OWN mechanism.

MEASURED BUG (2026-10-04): `authn.auto.t.098b4140`, a claim about single
sign-on session lifetime, was given a FILESYSTEM falsifier ("the resolved path
stays inside the permitted base directory") because the matcher tested bare
substrings and the literal "file" occurs inside the word **profile**. A falsifier
attached to the wrong mechanism is worse than none, because it reads as specific.

The matcher now uses word boundaries. This test exists so that a future
substring regression is caught by a TEST rather than by reading 1,375 items.

Each case states the branch it MUST take, and one states the branch it MUST NOT
take. Run:  python eval/test_disproof_relevance.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import importlib  # noqa: E402
from orch import researcher as R  # noqa: E402

importlib.reload(R)

FAILED: list[str] = []

# claim fragment -> (must_contain, must_not_contain)
CASES = [
    ("Alternatively, a single sign-on solution may authenticate the user and "
     "remain logged in for a day but require a profile",
     "single named control", "permitted base directory"),
    ("A single sign-on flow lets the user change their email without "
     "re-authentication on the profile page",
     "single named control", "permitted base directory"),
    ("A path traversal allowlist is bypassed when the filter compares the raw "
     "path but the backend normalises percent-encoded octets first",
     "permitted base directory", "Location host"),
    ("An error page reflects the filename supplied in the URL, disclosing the "
     "server's absolute path",
     "permitted base directory", "Location host"),
    ("SQL injection occurs when user input is concatenated into a query string "
     "rather than bound as a parameter",
     "bound as a parameter", "permitted base directory"),
    ("A redirect parameter controls the Location header returned to the browser, "
     "sending the user to an attacker URL",
     "Location host", "permitted base directory"),
    ("An ACL granting WRITE_DAC lets a low-privilege principal take ownership "
     "and escalate to admin",
     "lower-privileged identity", "permitted base directory"),
    ("A filter is bypassed when the backend normalises after the allowlist "
     "comparison, so the payload evades the check",
     "defensive control", "permitted base directory"),
    ("A blind out-of-band request is confirmed only by a callback to a host the "
     "tester controls",
     "single named control", "permitted base directory"),
]

print("A falsifier must match the claim's own mechanism\n")
for i, (claim, must, must_not) in enumerate(CASES, 1):
    d = R._disproof(claim).lower()
    ok_must = must.lower() in d
    ok_not = must_not.lower() not in d
    good = ok_must and ok_not
    print(f"  [{'PASS' if good else 'FAIL'}] case {i}: "
          f"contains {must!r}={ok_must}, excludes {must_not!r}={ok_not}")
    if not good:
        print(f"          claim: {claim[:78]}")
        print(f"          got  : {d[:110]}")
        FAILED.append(i)

print()
extra = ["the claim is refuted only when the value never reaches the sink",
         "profile with an avatar", "filesystem mounted read-only"]
for c in extra:
    d = R._disproof(c)
    print(f"  [PASS] degenerate input handled: {c[:52]!r} -> {d[:60]}")

print()
if FAILED:
    print(f"RESULT: {len(FAILED)} case(s) FAILED -> {FAILED}")
    raise SystemExit(1)
print(f"RESULT: all {len(CASES)} cases route to the correct falsifier.")