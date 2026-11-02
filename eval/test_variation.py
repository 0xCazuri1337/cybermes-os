"""Prove the variation model is REAL, not cosmetic — validated both ways.

A variation model that always returns one profile is worse than none: it
manufactures the appearance of rigour. So every check here has a known input
that MUST produce the opposite verdict, and the suite fails loudly if the model
cannot tell them apart.

  T1  discrimination: items that differ in encoding resolve to DIFFERENT axes
  T2  evidence-bound: an item mentioning nothing resolves to the honest default,
      not an invented stack of variation
  T3  no single (axis,value) pair silently dominates a real corpus
  T4  audit_variation REJECTS a synthetic all-identical playbook
  T5  audit_variation ACCEPTS a genuinely varied one
  T6  every value referenced by detect_axes exists in DIMENSIONS (no dangling)
  T7  escalation returns something concrete, never filler

Run:  python eval/test_variation.py     Exit 0 = real variation.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import variation as V  # noqa: E402

FAILED: list[str] = []
PASSED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


print("T1  discrimination — different mechanisms resolve to different axes")
cases = [
    ("A percent-encoded traversal that the backend decodes after the filter "
     "compares the raw string.", "encoding_layer", "url"),
    ("The value arrives twice percent-encoded so a single-decode filter misses "
     "it.", "encoding_layer", "double"),
    ("Fullwidth solidus and fullstop survive the filter and are converted by "
     "the Unicode normalisation step.", "encoding_layer", "unicode"),
    ("The payload is nested inside an uploaded archive and re-read by the "
     "extractor.", "parser_differential", "container"),
]
for text, axis, want in cases:
    got = V.detect_axes(text, "")
    check(f"detects {axis}={want}", got.get(axis) == want,
          f"got {got.get(axis)} from {text[:40]!r}")

print()
print("T2  evidence-bound — a content-free item gets the honest default")
empty = V.detect_axes("A value is assigned without validation.", "")
check("no invented encoding layer", "encoding_layer" not in empty, str(empty))
check("no invented request_location", "request_location" not in empty, str(empty))
check("parser_differential defaults to 'single'", empty.get("parser_differential") == "single",
      str(empty.get("parser_differential")))

print()
print("T3  real corpus — variation is actually discriminating")
import json  # noqa: E402
import glob  # noqa: E402
import sqlite3  # noqa: E402

con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
con.row_factory = sqlite3.Row
rows = con.execute("""
    SELECT i.item_key, i.claim, i.body FROM item i
    JOIN quality q ON q.item_id = i.id
    WHERE i.status='active' AND q.validation_state='high_confidence'
""").fetchall()
entries = []
for r in rows:
    ax = V.detect_axes(r["claim"] or "", r["body"] or "")
    # carry the RENDERED instructions, exactly as build_playbook() does, so the
    # audit sees what a hunter would actually read
    entries.append({"item_key": r["item_key"], "axes": ax,
                    "variation": V.variation_block(ax),
                    "escalation": V.escalation(ax)})

audit = V.audit_variation(entries)
print(f"       {audit['entries']} entries | {audit['distinct_profiles']} distinct "
      f"profiles | dominant {audit['dominant_profile_share']}")
print(f"       axes taking >1 value: "
      f"{ {k: len(v) for k, v in audit['axes_with_multiple_values'].items()} }")
check("corpus yields >1 distinct variation profile", audit["distinct_profiles"] > 1,
      f"{audit['distinct_profiles']}")
check("corpus variation passes the anti-gaming audit", audit["ok"],
      audit["verdict"])
check("at least 3 axes discriminate on the real corpus",
      len(audit["axes_with_multiple_values"]) >= 3,
      str({k: len(v) for k, v in audit["axes_with_multiple_values"].items()}))

print()
print("T4  audit_variation REJECTS a cosmetic playbook (it must be able to fail)")
fake = [{"item_key": f"x{i}", "axes": {"parser_differential": "single",
                                       "request_location": "query"}}
        for i in range(50)]
a4 = V.audit_variation(fake)
check("50 identical-axis entries are REJECTED", not a4["ok"], a4["verdict"])
check("rejection names the dominant profile", a4["dominant_profile_share"] == 1.0,
      str(a4["dominant_profile_share"]))

print()
print("T5  audit_variation ACCEPTS a genuinely varied playbook")
good = []
combos = [("container", "body_json", "oob"), ("front_back", "query", "differential"),
          ("single", "path", "content"), ("container", "header", "state"),
          ("front_back", "multipart", "oob"), ("single", "body_form", "differential")]
for i, (pd, rl, cf) in enumerate(combos):
    ax = {"parser_differential": pd, "request_location": rl, "confirmation": cf}
    good.append({"item_key": f"g{i}", "axes": ax,
                 "variation": V.variation_block(ax),
                 "escalation": V.escalation(ax)})
a5 = V.audit_variation(good)
check("varied playbook is ACCEPTED", a5["ok"], a5["verdict"])
check("accepted playbook reports >1 distinct profile", a5["distinct_profiles"] > 1,
      str(a5["distinct_profiles"]))

print()
print("T6  no dangling axis/value references")
bad = []
for text in ["percent-encoded payload", "fullwidth solidus", "nested archive",
             "out-of-band callback", "query parameter", "http/2 frames",
             "cross-tenant second identity", "double-encoded"]:
    for axis, val in V.detect_axes(text, "").items():
        if axis not in V.DIMENSIONS:
            bad.append(f"{axis} unknown")
        elif val not in V.DIMENSIONS[axis]["values"]:
            bad.append(f"{axis}={val} not a declared value")
check("every detected axis/value is declared in DIMENSIONS", not bad, str(bad[:5]))

print()
print("T7  escalation is concrete, never filler")
esc = V.escalation({"encoding_layer": "url", "request_location": "query",
                    "transport_path": "proxied"})
check("escalation returns >=3 concrete steps", len(esc) >= 3, str(len(esc)))
check("escalation mentions the encoding ladder",
      any("ladder" in s.lower() for s in esc))
check("escalation tells you when to STOP (a flat result is a result)",
      any("RESULT" in s for s in esc), str(esc[-1][:60]))
esc_none = V.escalation({})
check("escalation works with no axes detected", len(esc_none) >= 2,
      str(len(esc_none)))

print()
print("T8  THE REVIEWER'S GAMING CASE — distinct labels, identical instructions")
# Exactly what the adversarial review warned about: every entry declares a
# DIFFERENT axis combination, yet all of them emit the SAME instruction text.
# The profile gate alone would pass this. The instruction gate must not.
gamed = []
for i in range(50):
    ax = {"encoding_layer": ["url", "double", "unicode", "json_esc"][i % 4],
          "request_location": ["query", "path", "body_json", "header"][i % 4]}
    gamed.append({"item_key": f"game{i}", "axes": ax,
                  "variation": ["- **SAME** do the same thing; observe nothing new."],
                  "escalation": ["- **SAME** also the same."]})
a8 = V.audit_variation(gamed)
check("40+ distinct labels + ONE instruction set is REJECTED", not a8["ok"],
      a8["verdict"])
check("rejection is driven by the instruction gate",
      a8["distinct_instruction_sets"] == 1 and a8["dominant_instruction_share"] == 1.0,
      f"sets={a8['distinct_instruction_sets']} share={a8['dominant_instruction_share']}")
check("profiles ARE distinct (so the old gate would have passed)",
      a8["distinct_profiles"] > 1, f"profiles={a8['distinct_profiles']}")

print()
print("T9  real variation also survives the instruction gate")
con2 = sqlite3.connect(str(ROOT / "db" / "wks.db"))
con2.row_factory = sqlite3.Row
real = []
for r in con2.execute("""SELECT i.item_key,i.claim,i.body FROM item i
    JOIN quality q ON q.item_id=i.id
    WHERE i.status='active' AND q.validation_state='high_confidence'"""):
    ax = V.detect_axes(r["claim"] or "", r["body"] or "")
    real.append({"item_key": r["item_key"], "axes": ax,
                 "variation": V.variation_block(ax),
                 "escalation": V.escalation(ax)})
a9 = V.audit_variation(real)
check("real corpus passes BOTH gates", a9["ok"], a9["verdict"])
check("real corpus instruction sets are numerous",
      a9["distinct_instruction_sets"] > 20, str(a9["distinct_instruction_sets"]))
check("no single instruction set dominates the real corpus",
      a9["dominant_instruction_share"] < 0.60,
      str(a9["dominant_instruction_share"]))

print()
if FAILED:
    print(f"RESULT: {len(PASSED)} pass, {len(FAILED)} FAIL -> {FAILED}")
    raise SystemExit(1)
print(f"RESULT: {len(PASSED)} pass, 0 fail — the variation model discriminates.")