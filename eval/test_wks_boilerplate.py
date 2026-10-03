"""T28 — boilerplate must never corroborate a technical claim.

THE DEFECT (measured on the live corpus, not hypothesised).
An item is promoted when >=2 publisher ORGS cite it. The gate counts orgs and
never asks whether the quoted text is ABOUT the claim. So a generic sentence
from an unrelated page satisfies it:

  item   authn.chain_link.saml_signature_wrapping_to_account_takeover
  claim  "a SAML relying party that does not pin which assertion it trusts
          accepts an attacker-injected second assertion"
  quote  "Maintaining and keeping track of a user's session is an integral
          part of web applications."   <- academy.hackthebox.com, an unrelated
                                          HTTP-misconfiguration course page

MEASURED SCALE: 444 of 1111 active items (40%) cite a quote that is ALSO cited
by a different bug class. Worst classes: ad_ntlm 95%, prototype_pollution 91%,
password_attacks 90%. The repeated text is course boilerplate --
"We will discuss how to identify, exploit, and prevent TLS attacks" backing an
LDAP item, "Buffer overflows are common vulnerabilities" backing 11 classes.

WHY THE EXISTING GATES MISS IT. `verify_quotes` asks "is this text ON the
cited page?" -- and it is. Two orgs are cited, so the count passes. Neither
question is "is this text about the thing the item claims". That is an
ENTAILMENT question, and answering it honestly needs an LLM; what can be
decided mechanically, and is decided here, is the weaker and still damning
question: **is this text generic boilerplate that many unrelated items share?**

Two independent signals, because either alone is gameable:
  * REUSE  -- the same quote cited by items in >=2 different bug classes
  * TOPICAL -- none of the class's own vocabulary appears in the quote

An item failing BOTH is not evidence for its claim. It is decoration.

Run:  python eval/test_wks_boilerplate.py [--report]
Exit: non-zero when any active item fails both tests (report mode: always 0).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402
from wks import taxonomy_ext  # noqa: E402


def class_vocab(class_id: str) -> set[str]:
    """Vocabulary that would make a quote plausibly ABOUT this class.

    Deliberately includes the class id's own words and its catalog aliases, so
    an RDP item quoting the RDP specification counts as topical. An earlier,
    narrower version flagged `rdp.technique.rdp_reachable_is_access_reachable`
    for citing learn.microsoft.com's Remote Desktop Protocol page -- which is
    exactly the citation that item should have. A detector that punishes the
    right citation gets switched off, so the vocabulary has to be generous
    and the REUSE signal has to carry the real weight.
    """
    words = set(class_id.replace("_", " ").lower().split())
    for row in taxonomy_ext.CATALOG:
        if row[0] == class_id:
            for a in row[6]:
                words |= set(a.replace("-", " ").replace("_", " ").lower().split())
    # Drop generic noise that would make everything look topical.
    stop = {"and", "the", "for", "with", "from", "that", "this", "using",
            "class", "vuln", "attack", "attacks", "using", "does", "when"}
    return {w for w in words if len(w) > 3 and w not in stop}


def scan(limit: int = 0) -> list[dict]:
    con = store.connect(config.DB_PATH)
    try:
        reuse = {r["quote"] for r in con.execute(
            """SELECT q.quote FROM item_source q JOIN item i ON i.id=q.item_id
                WHERE i.status='active' AND LENGTH(q.quote)>40
                GROUP BY q.quote HAVING COUNT(DISTINCT i.class_id)>1""")}
        rows = con.execute(
            """SELECT i.item_key, i.class_id, i.claim, s.url, q.quote
                 FROM item i JOIN item_source q ON q.item_id=i.id
                 JOIN source s ON s.id=q.source_id
                WHERE i.status='active'""").fetchall()
    finally:
        con.close()

    bad, seen = [], set()
    for r in rows:
        key, cid, quote = r["item_key"], r["class_id"], r["quote"] or ""
        if quote not in reuse or len(quote) < 40:
            continue
        ql = quote.lower()
        vocab = class_vocab(cid)
        topical = any(w in ql for w in vocab)
        if topical:
            continue
        if key in seen:
            continue
        seen.add(key)
        bad.append({"item_key": key, "class_id": cid,
                    "url": r["url"], "quote": quote, "claim": r["claim"]})
    return bad[:limit] if limit else bad


def main() -> int:
    report = "--report" in sys.argv
    bad = scan(limit=0 if report else 12)
    total = len(bad)
    print(f"=== T28 boilerplate corroboration ===")
    print(f"active items whose ONLY support is cross-class generic text: {total}")
    if not total:
        print("  PASS  no item rests on shared boilerplate")
    else:
        for b in bad:
            print(f"  BOILERPLATE  {b['item_key']}")
            print(f"      class  {b['class_id']}")
            print(f"      quote  {b['quote'][:100]}")
            print(f"      url    {b['url'][:100]}")
        if not report:
            print(f"\nFAILED: {total} item(s) cite text that appears in other "
                  f"classes AND contains none of this class's vocabulary.")
            print("Re-run with --report for the full list.")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
