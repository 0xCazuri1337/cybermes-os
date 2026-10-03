"""Corpus triage: decide what, if anything, survives from a legacy knowledge set.

Run:  python -m wks.cli audit-legacy <dir> [--apply]

The previous system's corpus was quarantined after the Selection-C rebuild. This
script measures it against the CURRENT gate instead of trusting its own
`validation_status` labels, then writes an import manifest.

Design rules:
  * Nothing is deleted. Survivors are COPIED into the new schema; the legacy
    tree stays exactly where it is (brief §3: recoverable state).
  * An item is only imported if it can be re-earned: real URLs on >= 2
    publisher hosts, a falsifiable claim, and no invented cross-references.
  * Everything else is recorded as rejected WITH a reason, so the decision is
    auditable rather than silent.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wks import store  # noqa: E402

LEGACY_FIELDS = ("knowledge_id", "title", "content", "summary", "category",
                 "source_refs", "confidence", "cross_checks", "technique")

# Cross-check placeholders the previous corpus used instead of real evidence.
_FAKE_REF = re.compile(r"^(ref\d*|source\d*|src\d*|cite\d*|n/?a|none|todo)$", re.I)

# The corpus also absorbed the test suite's own fixtures ("RAG Test 0",
# "CLI Validate Test"), each replicated hundreds of times. These are not weak
# knowledge — they are not knowledge at all, and their presence means the old
# ingestion path could not tell a test fixture from a research finding.
_FIXTURE = re.compile(
    r"\b(rag test|cli validate test|test fixture|sample item|lorem ipsum|"
    r"asdf|foo bar|dummy (item|knowledge))\b",
    re.I,
)


def _hosts(source_refs) -> set[str]:
    out = set()
    for r in source_refs or []:
        url = r.get("source_url") if isinstance(r, dict) else None
        if url:
            h = urlparse(url).hostname or ""
            out.add(h[4:] if h.startswith("www.") else h)
    return {h for h in out if h}


def load_legacy(root: Path) -> list[dict]:
    items: list[dict] = []
    for f in sorted(root.rglob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and d.get("knowledge_id"):
            d["__path"] = str(f)
            items.append(d)
    return items


def classify(rec: dict) -> dict:
    """Apply the current gate's hard rules to a legacy record."""
    claim = (rec.get("title") or "").strip()
    content = (rec.get("content") or "").strip()
    srefs = rec.get("source_refs") or []
    hosts = _hosts(srefs)
    checks = (rec.get("cross_checks") or [])
    fake = [c for c in checks if isinstance(c, str) and _FAKE_REF.match(c.strip())]

    reasons = []
    if not srefs:
        reasons.append("NO_SOURCES")
    if len(srefs) < 2:
        reasons.append("INSUFFICIENT_SOURCES")
    if len(hosts) < 2:
        reasons.append(f"INSUFFICIENT_PUBLISHER_HOSTS({len(hosts)}<2)")
    if fake:
        reasons.append(f"FABRICATED_REFS({len(fake)})")
    if len(claim) < 40:
        reasons.append("VAGUE_CLAIM")
    # The corpus's signature shape: a truncated teaser ending in an ellipsis.
    if content.endswith("...") or len(content) < 200:
        reasons.append("TRUNCATED_TEASER")

    return {
        "knowledge_id": rec.get("knowledge_id"),
        "path": rec.get("__path"),
        "title": claim,
        "category": rec.get("category"),
        "claim_chars": len(claim),
        "content_chars": len(content),
        "n_sources": len(srefs),
        "hosts": sorted(hosts),
        "sources_have_quotes": bool(
            any(isinstance(r, dict) and (r.get("quote") or r.get("locator"))
                for r in srefs)
        ),
        "looks_like_test_fixture": _FIXTURE.search(claim) is not None,
        "reasons": reasons,
        "importable": not reasons,
    }


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    root = Path(argv[0])
    apply = "--apply" in argv

    recs = load_legacy(root)
    print(f"legacy records found: {len(recs)}")
    verdicts = [classify(r) for r in recs]

    reason_counts = Counter(r for v in verdicts for r in v["reasons"])
    importable = [v for v in verdicts if v["importable"]]

    print(f"\nimportable under the current gate: {len(importable)}"
          f"  ({100.0*len(importable)/max(len(verdicts),1):.1f}%)")
    print("\nrejection reasons (a record can have several):")
    for r, n in reason_counts.most_common():
        print(f"  {n:6}  {r}")

    title_dupes = Counter(v["title"] for v in verdicts if v["title"])
    dup_groups = sum(1 for t, n in title_dupes.items() if n > 1)
    print(f"\nduplicate title groups: {dup_groups}")
    print("most repeated titles:")
    for t, n in title_dupes.most_common(5):
        print(f"  {n:5}x  {t[:80]}")

    manifest = {
        "source_root": str(root),
        "records": len(verdicts),
        "importable": len(importable),
        "rejected": len(verdicts) - len(importable),
        "reason_counts": dict(reason_counts),
        "duplicate_title_groups": dup_groups,
        "verdicts": verdicts,
    }
    out = Path(__file__).resolve().parent.parent / "state" / "legacy-audit.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nmanifest: {out}")

    if not apply:
        print("\n(dry run — pass --apply to import the importable records)")
        return 0

    con = store.open_db(create=True)
    # Deliberately no import loop. Zero records qualify today, and even a
    # qualifying record would still need two things this script cannot supply:
    # a bug-class mapping decision, and a curator-quoted evidence span (a URL
    # alone is not evidence). See state/legacy-audit.json for the verdict per
    # record.
    survivors = [v for v in importable if v["sources_have_quotes"]]
    con.close()
    print(f"\nimported: 0 of {len(verdicts)}")
    print(f"records passing the gate: {len(importable)}; "
          f"of those, carrying curator quotes: {len(survivors)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
