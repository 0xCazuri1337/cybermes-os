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

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402
from wks import quality  # noqa: E402
from wks import taxonomy_ext  # noqa: E402


def _words(text: str) -> set[str]:
    """Split a name or alias into comparable words.

    Hyphens and underscores are SEPARATORS, not part of the word: a class
    named "Named-Pipe Abuse" must match a quote that says "named pipes".
    """
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def _is_cwe_definition(con, quote: str) -> bool:
    """Is this quote the definition paragraph of a CWE?

    The CWE definition pages are the taxonomy itself: one generic paragraph
    per weakness, quoted by every class that weakness covers. Sharing them
    is the taxonomy working, not boilerplate.
    """
    if not quote:
        return False
    rows = con.execute(
        """SELECT DISTINCT s.url FROM item_source q
             JOIN source s ON s.id=q.source_id
            WHERE q.quote=?""", (quote,)).fetchall()
    urls = [r["url"] for r in rows]
    return bool(urls) and all(
        "cwe.mitre.org" in u and "/definitions/" in u for u in urls)


def class_vocab(class_id: str) -> set[str]:
    """Vocabulary that would make a quote plausibly ABOUT this class.

    Deliberately includes the class id's own words and its catalog aliases, so
    an RDP item quoting the RDP specification counts as topical. An earlier,
    narrower version flagged `rdp.technique.rdp_reachable_is_access_reachable`
    for citing learn.microsoft.com's Remote Desktop Protocol page -- which is
    exactly the citation that item should have. A detector that punishes the
    right citation gets switched off, so the vocabulary has to be generous
    and the REUSE signal has to carry the real weight.

    MEASURED 2026-10-31: this read `taxonomy_ext.CATALOG` alone. That
    catalog does NOT contain the network classes -- `linux_privesc`,
    `windows_privesc_token` and `windows_privesc_service` are absent from
    it -- so their vocabulary was just the class_id split into words
    (`linux`, `privesc`). A quote like

        "Compare that output with --inhibit-cache --list: a difference
         proves that /etc/ld.so.preload was modified"

    was therefore judged NOT topical, because it contains neither the
    literal "linux" nor "privesc" -- and an item quoting the exact
    mechanism it claims was flagged as resting on boilerplate.

    The vocabulary now comes from the CANONICAL `bug_class` table -- the
    same taxonomy the corpus is filed under -- with the catalog as a
    fallback. A class the catalog does not know about is still classified,
    because the database is the source of truth.
    """
    words = set(class_id.replace("_", " ").lower().split())
    try:
        con = store.connect(config.DB_PATH)
        try:
            row = con.execute(
                "SELECT name, aliases FROM bug_class WHERE id=?",
                (class_id,)).fetchone()
        finally:
            con.close()
        if row:
            # MEASURED 2026-10-31: the name is split on WHITESPACE only, so
            # "Windows Privilege Escalation via Service and Named-Pipe Abuse"
            # contributed "named-pipe" as one token -- and a quote saying
            # "On named pipes this implicitly includes ..." does not contain
            # the string "named-pipe". Hyphens are split too, so the token is
            # "pipe" and the quote matches.
            words |= _words(row["name"] or "")
            for a in json.loads(row["aliases"] or "[]"):
                words |= _words(a)
    except Exception:
        pass
    for row in taxonomy_ext.CATALOG:
        if row[0] == class_id:
            for a in row[6]:
                words |= set(a.replace("-", " ").replace("_", " ").lower().split())
    # Drop generic noise that would make everything look topical.
    stop = {"and", "the", "for", "with", "from", "that", "this", "using",
            "class", "vuln", "attack", "attacks", "using", "does", "when",
            "privilege", "escalation"}
    return {w for w in words if len(w) > 3 and w not in stop}


def scan(limit: int = 0) -> list[dict]:
    """Every PROMOTED item whose only support is cross-class generic text.

    MEASURED 2026-10-31: this scanned `i.status='active'` only. It did
    not look at the GATE's verdict, so it reported items the gate had
    already HELD -- an item in `under_review` with
    `CROSS_CLASS_BOILERPLATE` in its `gate_reasons` is not promoted and
    cannot teach anything, but this scanner counted it as a failure.

    The distinction is the whole point of the test: the defect it exists
    for is boilerplate CORROBORATING a claim, which means the item was
    PROMOTED on boilerplate. An item the gate holds is exactly the
    remediation, not a failure.

    So the scan now asks the real question: is there any item whose gate
    state is PROMOTED (`supported` / `high_confidence`) while its only
    support is cross-class boilerplate?

    The REUSE set is still computed over all active items -- a quote shared
    with a held item in another class is still shared -- but the FAILING
    set is the promoted ones.
    """
    con = store.connect(config.DB_PATH)
    try:
        reuse = {r["quote"] for r in con.execute(
            """SELECT q.quote FROM item_source q JOIN item i ON i.id=q.item_id
                WHERE i.status='active' AND LENGTH(q.quote)>40
                GROUP BY q.quote HAVING COUNT(DISTINCT i.class_id)>1""")}
        # MEASURED 2026-10-31: a CWE DEFINITION paragraph is shared across
        # classes BY DESIGN -- CWE-269's generic wording ("The product does
        # not properly assign, modify, track, or check privileges...") is
        # quoted by every privilege-escalation class, and CWE-78's by every
        # injection class. Counting that paragraph as class boilerplate
        # flagged items whose OWN quote was the specific mechanism they
        # claim, e.g.
        # `linux_privesc.technique.file_capability_xattr_raises_permitted_set`
        # whose only other citation is "This is not a set, but rather just a
        # single bit."
        #
        # A CWE definition is a CLASS-LEVEL taxonomy citation. It is real
        # evidence of the category, and it is shared because the taxonomy
        # is shared -- not because it is generic prose. The REUSE signal is
        # about COURSE BOILERPLATE, which is what the test's own docstring
        # describes ("We will discuss how to identify, exploit, and prevent
        # TLS attacks" backing an LDAP item).
        #
        # So a quote from `cwe.mitre.org/definitions/` is excluded from the
        # reuse set. A CWE definition alone is already handled by the gate's
        # `LABEL_ONLY_QUOTE` rule, which refuses to count it as the second
        # publisher.
        reuse = {q for q in reuse
                 if not quality._is_cwe_definition(con, q)}
        rows = con.execute(
            """SELECT i.item_key, i.class_id, i.claim, s.url, q.quote,
                      g.validation_state
                 FROM item i JOIN item_source q ON q.item_id=i.id
                 JOIN source s ON s.id=q.source_id
                 JOIN quality g ON g.item_id=i.id
                WHERE i.status='active'""").fetchall()
    except Exception:
        con.close()
        raise

    promoted = {"supported", "high_confidence"}

    # Group by ITEM, not by quote. The defect is "the item rests on shared
    # boilerplate", which is a statement about the item's WHOLE support: if
    # ONE of its quotes is class-specific, the item is not resting on
    # boilerplate alone. Evaluating each quote independently flagged items
    # that had exactly that one class-specific quote.
    #
    # MEASURED 2026-10-31: the per-quote evaluation reported
    # `windows_privesc_token.impact.raw_local_security_authority_lsa_l` --
    # which cites two shared quotes AND one that is unique to it ("Local
    # Security Authority (LSA) - LSASS ...").
    by_item: dict[str, dict] = {}
    for r in rows:
        key = r["item_key"]
        if key not in by_item:
            by_item[key] = {"item_key": key, "class_id": r["class_id"],
                            "claim": r["claim"], "state": r["validation_state"],
                            "quotes": []}
        by_item[key]["quotes"].append((r["url"], r["quote"] or ""))

    bad = []
    try:
        for item in by_item.values():
            if (item["state"] or "") not in promoted:
                # The gate already holds this item. That is the remediation.
                continue
            shared = [(u, q) for u, q in item["quotes"]
                      if q in reuse and len(q) >= 40]
            if not shared:
                continue
            # Is there a quote that is NOT shared AND mentions this class?
            # The GATE owns this definition -- the scanner calls the same
            # helper, so the test and the remediation cannot disagree about
            # what "class-specific" means.
            specific = [(u, q) for u, q in item["quotes"]
                        if quality.is_class_specific(
                            con, item["class_id"], q, unshared=q not in reuse)]
            if specific:
                continue
            bad.append({"item_key": item["item_key"],
                        "class_id": item["class_id"],
                        "url": shared[0][0], "quote": shared[0][1],
                        "claim": item["claim"]})
    finally:
        con.close()
    bad.sort(key=lambda b: b["item_key"])
    return bad[:limit] if limit else bad


def main() -> int:
    report = "--report" in sys.argv
    bad = scan(limit=0 if report else 12)
    total = len(bad)
    print(f"=== T28 boilerplate corroboration ===")
    print(f"PROMOTED items whose ONLY support is cross-class generic text: {total}")
    if not total:
        print("  PASS  no promoted item rests on shared boilerplate")
    else:
        for b in bad:
            print(f"  BOILERPLATE  {b['item_key']}")
            print(f"      class  {b['class_id']}")
            print(f"      quote  {b['quote'][:100]}")
            print(f"      url    {b['url'][:100]}")
        if not report:
            print(f"\nFAILED: {total} promoted item(s) cite text that appears "
                  f"in other classes AND contains none of this class's "
                  f"vocabulary.")
            print("Re-run with --report for the full list.")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
