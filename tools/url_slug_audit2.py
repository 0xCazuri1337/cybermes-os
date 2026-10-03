"""Corrected URL-slug audit, after the first version produced 9 false positives.

MEASURED: v1 flagged 9 promoted items as "class vocabulary appears only inside a
URL/slug". A detail pass showed ALL NINE were prose:

    xss          "Reflected cross-site scripting (or XSS) arises when an ..."
    ssrf         "... from the application, then it is vulnerable to SSRF."
    clickjacking "Content-Security-Policy: ... frame-ancestors 'none';"
    namespace    "Sharing the host namespaces must be disallowed."
    hijack       "Adding a user-writable directory to the Machine PATH crea..."

The bug was in the STRIPPER, not the corpus. Its slug pattern
r`(?:^|[\s/\-])(?:\d{2,}-)*[a-z]+(?:[-_][a-z0-9]{2,})+` deletes any hyphenated
lowercase compound, which is most technical English:

    content-type    -> (EMPTY)
    cross-site      -> (EMPTY)
    read-only       -> (EMPTY)
    case-sensitive  -> (EMPTY)
    non-ascii       -> (EMPTY)

So "cross-site scripting" was deleted as if it were a slug, and `xss` looked like
it had no prose vocabulary. **A false positive from an over-aggressive stripper is
worse than no audit**, because it invites refiling correct items.

The corrected version strips only:
  * real URLs (scheme-anchored, or a known TLD)
  * markdown link TARGETS `](...)`
  * a `word/word/word` PATH shape
and leaves hyphenated prose alone. Then it re-checks.

Also reports the stripper's self-test, so the checker is validated in BOTH
directions like every other checker here: prose must SURVIVE, a URL must NOT.
"""
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import relevance, store  # noqa: E402

URL = re.compile(r"(?:https?://|ftp://)\S+|(?<![\w./])(?:www\.)[\w.-]+\.\w{2,}/\S*")
MDLINK = re.compile(r"\]\([^)]*\)")
TLD_PATH = re.compile(
    r"(?<![\w-])[\w-]+\.(?:com|org|net|io|dev|app|me|ru|blog|site|co|uk|info)"
    r"(?:/\S*)?", re.I)
PATH_SHAPE = re.compile(r"\b\w+/\w+/\w+\b")
# A slug with no TLD ("boolean-based-sqli-injection") is only a slug when it has
# >=3 hyphenated lowercase segments. "cross-site" and "content-type" have two and
# must SURVIVE -- the self-test below refuses to run without that, because the
# first version of this audit deleted hyphenated technical English and invented
# nine findings from it.
DEEP_SLUG = re.compile(r"(?<![\w-])[a-z]+(?:-[a-z0-9]+){2,}(?![\w-])")

SELFTEST_KEEP = ["cross-site scripting", "content-type", "read-only",
                 "case-sensitive", "non-ascii", "writable directory",
                 "cross-site request forgery", "user-supplied input"]
SELFTEST_DROP = ["https://example.com/xss", "www.portswigger.net/xss",
                 "boolean-based-sqli-injection",
                 "](https://medium.com/some-article-about-xss)"]


def strip(s):
    s = MDLINK.sub("](URL)", s)
    s = URL.sub(" ", s)
    s = TLD_PATH.sub(" ", s)
    s = PATH_SHAPE.sub(" ", s)
    s = DEEP_SLUG.sub(" ", s)
    return s


def selftest():
    ok = True
    for s in SELFTEST_KEEP:
        if strip(s).strip() != s.strip():
            print("  STRIPPER EATS PROSE: %r -> %r" % (s, strip(s).strip()))
            ok = False
    for s in SELFTEST_DROP:
        if strip(s).strip() == s.strip():
            print("  STRIPPER KEEPS A URL: %r" % s)
            ok = False
    print("  stripper self-test: %s" % ("PASS" if ok else "FAIL"))
    return ok


def main():
    con = store.connect()
    print("=" * 76)
    print("URL-SLUG VOCABULARY AUDIT (corrected stripper)")
    print("=" * 76)
    print("  v1 reported 9 items; a detail pass showed all 9 were PROSE and the")
    print("  v1 stripper was deleting hyphenated technical English.")
    print()
    if not selftest():
        print("\n  REFUSING TO REPORT: the checker has not been validated in both")
        print("  directions, and an unvalidated checker manufactures findings.")
        return 1

    rows = list(con.execute(
        "SELECT i.id, i.class_id, i.claim, x.quote"
        "  FROM item i"
        "  JOIN quality q ON q.item_id=i.id"
        "  JOIN item_source x ON x.item_id=i.id"
        " WHERE q.validation_state='high_confidence' AND i.status='active'"))
    per = collections.defaultdict(lambda: {"c": None, "claim": "", "q": []})
    for r in rows:
        d = per[r["id"]]
        d["c"] = r["class_id"]
        d["claim"] = r["claim"] or ""
        d["q"].append(r["quote"] or "")

    def hits(text, vocab):
        out = []
        for t in vocab:
            rx = re.escape(t).replace(r"\ ", r"\s+")
            if re.search(r"(?<![a-z0-9])" + rx + r"(?![a-z0-9])", text, re.I):
                out.append(t)
        return out

    at_risk = []
    for iid, d in per.items():
        vocab = relevance.CLASS_VOCAB.get(d["c"]) or []
        if not vocab:
            continue
        full = " ".join(d["q"])
        clean = strip(full)
        hf, hc = hits(full, vocab), hits(clean, vocab)
        lost = [t for t in hf if t not in hc]
        if lost and not hc:
            at_risk.append((d["c"], d["claim"][:64], lost))

    print()
    print("  promoted items examined : %d" % len(per))
    print("  resting only on a URL  : %d" % len(at_risk))
    if not at_risk:
        print("  VERDICT: CLEAN. Every promoted item's class rests on prose, not on")
        print("  an outbound link slug. The earlier 9 were a stripper defect.")
    for cid, claim, lost in at_risk[:12]:
        print("     %-18s %-56s %s" % (cid, claim, lost))
    return 0


if __name__ == "__main__":
    sys.exit(main())