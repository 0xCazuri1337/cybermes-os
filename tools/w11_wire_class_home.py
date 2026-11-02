#!/usr/bin/env python
"""Wire the three wave-11 classes into CLASS_HOME (build_taxonomy.py).

WHY A SCRIPT AND NOT `patch`: the patch tool has silently re-indented this
file three times on the same anchor (a known trap on this host -- only the
linter catches it). The skill's own rule is to repair a re-indent by
rewriting the whole block from a script rather than patching again.

WHY THE EDIT IS NEEDED: `otp`, `rate_limit` and `eol_software` were registered
by `tools/reg_field_classes.py` with a `taxonomy_spec.CLASSES` row each but
never added to `CLASS_HOME`. The moment they held gated items,
`taxonomy_write.py --check` REFUSED to write the whole tree
("CLASS_HOME=None is not a CLASSES row") and masterprompt check c_54
(§54, the architecture auditor) went red. The guard was right; the map was
incomplete.

`rate_limit` has TWO candidate CLASSES rows. Chosen: `api/rest/rate-limit.md`,
because the class is defined by whether a security-relevant operation is
reachable at all -- an API property, not an authentication one. Recorded in the
comment so the choice is auditable rather than a silent coin flip.

Asserts, then verifies by RE-READING the module:
  * every path written is a real CLASSES row,
  * no existing CLASS_HOME entry changed,
  * the module still imports.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "taxonomy"))

# The paths are COPIED VERBATIM from the CLASSES rows. Never retype these from
# the class name -- that is exactly how the map drifted in the first place.
NEW: dict[str, str] = {
    "otp": "web/authentication/otp.md",
    "rate_limit": "api/rest/rate-limit.md",
    "eol_software": "web/configuration/eol-software.md",
}

BLOCK = '''
    # ---- wave 11: field-registered classes that had spec rows but no home --
    # MEASURED 2026-10-03: these were registered by tools/reg_field_classes.py
    # with a `taxonomy_spec.CLASSES` row each, but never wired here. Once they
    # held gated items, `taxonomy_write.py --check` REFUSED to write the whole
    # tree ("CLASS_HOME=None is not a CLASSES row") and masterprompt check c_54
    # (the architecture auditor, SS54) went red -- a mapping gap surfacing as a
    # tree-wide failure. The guard was right; the map was incomplete.
    #
    # `rate_limit` has TWO candidate CLASSES rows: `web/authentication/rate-limit.md`
    # ("Rate Limiting") and `api/rest/rate-limit.md` ("Rate Limit and Resource
    # Consumption"). Chosen: the API one, because the class is defined by whether
    # a security-relevant operation is reachable at all -- an API property, not
    # an authentication one. Recorded so the choice is auditable rather than a
    # silent coin flip.
'''

ANCHOR = "    # ---- NETWORK domain ---"


def main() -> int:
    target = ROOT / "tools" / "taxonomy" / "build_taxonomy.py"
    src = target.read_text(encoding="utf-8")

    from taxonomy_spec import CLASSES
    declared = {c[0] for c in CLASSES}
    for cid, path in NEW.items():
        if path not in declared:
            print(f"FATAL: {cid} -> {path!r} is not a CLASSES row; refusing")
            return 2

    if "wave 11: field-registered classes" in src:
        print("already wired (idempotent) -- verifying only")
    else:
        if src.count(ANCHOR) != 1:
            print(f"FATAL: anchor occurs {src.count(ANCHOR)}x, expected exactly 1")
            return 2
        block = BLOCK + "".join(f'    "{k}": "{v}",\n' for k, v in NEW.items()) + "\n"
        src = src.replace(ANCHOR, block + ANCHOR, 1)
        target.write_text(src, encoding="utf-8")
        print("wrote 3 CLASS_HOME entries")

    # Verify by RE-READING the module, never by trusting the write.
    for mod in ("build_taxonomy", "taxonomy_write"):
        sys.modules.pop(mod, None)
    from build_taxonomy import CLASS_HOME  # noqa: E402

    bad = [f"{c}={CLASS_HOME.get(c)!r}" for c, p in NEW.items() if CLASS_HOME.get(c) != p]
    if bad:
        print(f"FATAL: did not read back: {bad}")
        return 1
    print("verified from the imported module:")
    for c, p in NEW.items():
        print(f"  {c:<14} -> {p}   (a real CLASSES row: {p in declared})")
    print(f"CLASS_HOME entries: {len(CLASS_HOME)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
