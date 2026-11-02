"""Reject the boilerplate disproof at the gate.

MEASURED (recon mastery cycle): **586 of 1334 active items (44%)** carry this
exact disproof:

    "This is refuted if an authoritative source shows the described behaviour
     does not occur, does not grant access, or is already prevented by default
     framework configuration: "<the claim, quoted back>""

It looks rigorous and refutes nothing. It names no falsifying test for the
mechanism, quotes the claim as its own evidence, and asserts an authority would
refute it without saying which check distinguishes the claim from its negation.
R4 requires a disproof because "an item with no disproof is a checklist line,
not knowledge" -- but a disproof that cannot fail is the same defect wearing a
citation.

This is why the refile pass would have been whack-a-mole: the items are bad
BECAUSE the gate accepted them. Fix the gate, then the corpus self-classifies.

The corpus is NOT modified here. Run `python -m wks.cli gate` afterwards to see
how many items this demotes on its own.

    python -m wks.disproof --selftest   # both directions
    python -m wks.disproof --audit      # corpus-wide
"""
from __future__ import annotations

import json
import os
import re
import sqlite3

WKS = os.environ.get("WKS_ROOT", "")

# The template, verbatim, with the claim-quoting tail generalised.
TEMPLATE_RE = re.compile(
    r"this is refuted if an authoritative source shows the described "
    r"behaviour does not occur.*?framework configuration\s*:?\s*",
    re.I | re.S,
)

# A disproof is USELESS when it is only the template plus a restatement of the
# claim. Signals, in order of strength:
#   - matches the boilerplate at all          -> useless
#   - the only quoted span is the claim itself -> circular
# Genuine disproofs ("A refused AXFR is not a finding if...") do not match.
MIN_USEFUL_CHARS = 60


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def is_boilerplate(disproof: str) -> bool:
    """True when this disproof is the template, whatever follows it."""
    if not disproof:
        return False
    d = disproof.strip()
    if TEMPLATE_RE.search(d):
        return True
    # Near-miss: the template with light rewording.
    low = d.lower()
    if low.startswith("this is refuted if an authoritative source") and \
            "does not occur" in low:
        return True
    return False


def is_circular(disproof: str, claim: str) -> bool:
    """The disproof's substance is just the claim quoted back.

    MEASURED: the first version used a bare length floor (MIN_USEFUL_CHARS),
    which flagged a legitimate 24-byte disproof in `eval/test_wks.py`'s dry-run
    canary -- a real regression against existing green tests. Brevity is not
    circularity: a short disproof ("Wrong if the pool is empty") carries real
    information. So the test is now SUBSTANTIVE OVERLAP -- does the disproof
    merely restate the claim? -- with the length floor demoted to a guard
    against an EMPTY residue only.
    """
    if not disproof or not claim:
        return False
    residue = TEMPLATE_RE.sub("", disproof).strip().strip('"').strip()
    if not residue:
        return True
    r, c = _norm(residue), _norm(claim)
    if not r:
        return True
    # Circular when the disproof's words are (almost) the claim's words.
    rw, cw = set(r.split()), set(c.split())
    if rw and cw:
        overlap = len(rw & cw) / len(rw)
        if overlap >= 0.9:
            return True
    # Or when one is a prefix of the other, which is the same defect.
    if c.startswith(r[:60]) or r.startswith(c[:60]):
        return True
    return False


def reason_for(disproof: str, claim: str) -> str | None:
    """The gate reason, or None when the disproof carries real information."""
    if is_boilerplate(disproof):
        return ("BOILERPLATE_DISPROOF: the disproof is a fixed template that "
                "refutes nothing -- it names no falsifying test for this "
                "mechanism and quotes the claim as its own evidence")
    if is_circular(disproof, claim):
        return ("CIRCULAR_DISPROOF: the disproof restates the claim rather "
                "than stating what would make it false")
    return None


# --------------------------------------------------------------------------
# SELFTEST — both directions. The corpus's real items are the negative control:
# a genuine disproof must never be flagged, or this gate would reject evidence
# (the R17 failure mode).
# --------------------------------------------------------------------------
SELFTEST: list[tuple[str, str, bool, str]] = [
    # (claim, disproof, should_be_flagged, why)
    ("An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser",
     'This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target\'s browser"',
     True, "the measured template"),
    ("A zone transfer succeeds",
     "This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access: \"A zone transfer succeeds\"",
     True, "template with a short tail"),
    ("The cart total is mutable",
     "The cart total is mutable",
     True, "pure circularity"),
    # --- genuine disproofs: MUST NOT be flagged ---
    ("A zone-transfer attempt discloses the zone when a nameserver outside the declared secondary set serves it",
     "Wrong, and a refused AXFR is not a clean configuration, if the transfer "
     "succeeds from a nameserver that is not in the zone's declared secondary "
     "set, or if a secondaries-permitted ACL is missing so any address can "
     "pull the whole zone.",
     False, "a real disproof: names the falsifying condition"),
    ("A dangling CNAME permits takeover",
     "Not a finding if the CNAME target still claims the resource, or if the "
     "provider has an explicit opt-in that requires the claimant to prove "
     "ownership of the domain first.",
     False, "real disproof"),
    ("An IDOR exists when the object id is not authorised for the caller",
     "Refuted when the response is identical for both objects because the "
     "endpoint returns a shared, non-per-user resource, or when the id is "
     "fully random AND the check is server-side per request.",
     False, "real disproof"),
    ("A subdomain resolves to a decommissioned PaaS provider",
     "Refuted when the DNS record is a wildcard from the apex and therefore "
     "never claimed per-name, or when the provider has an explicit claim "
     "requirement in place.",
     False, "real disproof"),
    ("SSRF via the URL fetcher",
     "A 302 to an internal host that the fetcher does not follow is not an "
     "SSRF; the disproof is that the client-side redirect was never resolved "
     "server-side, shown by an identical response from a non-following proxy.",
     False, "real disproof"),
    # --- edge cases ---
    # --- the measured REGRESSION: brevity is not circularity. A 24-byte
    #     disproof in eval/test_wks.py's dry-run canary was flagged by the
    #     first version's length floor, turning a green suite red. ---
    ("dry-run canary claim for the ingest harness",
     "dry-run canary disproof", False,
     "REGRESSION GUARD: a short but distinct disproof must pass"),
    ("The pool is empty",
     "Wrong if the pool is empty", False,
     "short disproof, real information"),
    ("", "", False, "empty in, empty out: nothing to judge"),
    ("A claim", "", False, "no disproof is absence, handled by R4 not here"),
]


def selftest(verbose: bool = True) -> tuple[bool, list[str]]:
    fails = []
    for claim, disproof, should_flag, why in SELFTEST:
        got = reason_for(disproof, claim) is not None
        if got != should_flag:
            fails.append(f"expected flagged={should_flag}, got {got} -- {why}")
    if verbose:
        total = len(SELFTEST)
        print(f"wks.disproof selftest: {total - len(fails)}/{total} correct")
        for f in fails:
            print("  FAIL " + f)
        if not fails:
            print("  every template/circular disproof caught; every genuine "
                  "disproof preserved")
    return (not fails), fails


def audit(as_json: bool = False) -> dict:
    db = os.path.join(WKS, "db", "wks.db")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT id, item_key, class_id, claim, disproof FROM item "
        "WHERE status='active'").fetchall()
    flagged = []
    for r in rows:
        why = reason_for(r["disproof"], r["claim"])
        if why:
            flagged.append({"item_id": r["id"], "item_key": r["item_key"],
                            "class_id": r["class_id"], "reason": why,
                            "claim_head": (r["claim"] or "")[:90]})
    by_class: dict[str, int] = {}
    for f in flagged:
        by_class[f["class_id"]] = by_class.get(f["class_id"], 0) + 1
    out = {"active_items": len(rows), "flagged": len(flagged),
           "pct": round(100.0 * len(flagged) / len(rows), 1) if rows else 0.0,
           "by_class": dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
           "items": flagged}
    if as_json:
        print(json.dumps(out, indent=2))
        return out
    print(f"active={out['active_items']} BOILERPLATE_OR_CIRCULAR_DISPROOF="
          f"{out['flagged']} ({out['pct']}%)")
    print(f"worst classes: {list(out['by_class'].items())[:10]}")
    return out


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        ok, _ = selftest()
        return 0 if ok else 1
    audit(as_json="--json" in argv)
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))